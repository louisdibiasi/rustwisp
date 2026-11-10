//! The rate-limiting primitives behind flood protection. The shared ones lock internally and do
//! O(1) work per call; none of them block, so a worker never waits on another worker for long.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// Keys one limiter holds before it purges the expired ones on the spot.
const MAX_WINDOW_KEYS: usize = 262_144;
const MAX_BANDWIDTH_KEYS: usize = 262_144;
const OVERFLOW_KEY: &str = "{0}overflow";
/// The shared bucket for untracked keys admits this many clients worth of events per window.
const OVERFLOW_FACTOR: u32 = 64;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A fixed-window counter per key: `limit` events per `window_ms`, the window starting at the
/// first event. A limit of 0 is unlimited.
#[derive(Debug)]
pub struct Window {
    limit: u32,
    window_ms: u64,
    entries: Mutex<HashMap<String, (u64, u32)>>,
    last_purge: Mutex<u64>,
}

impl Window {
    pub fn new(limit: u32, window_ms: u64) -> Window {
        Window {
            limit,
            window_ms: if window_ms == 0 { 1000 } else { window_ms },
            entries: Mutex::new(HashMap::new()),
            last_purge: Mutex::new(0),
        }
    }

    /// Count one event for `key`. False when it is over the limit.
    pub fn allow(&self, key: &str, now_ms: u64) -> bool {
        if self.limit == 0 {
            return true;
        }
        let mut map = lock(&self.entries);
        if map.len() >= MAX_WINDOW_KEYS && !map.contains_key(key) {
            // Over capacity: shed the keys whose window has ended, at most once a second so a
            // flood of fresh keys cannot turn every call into a full scan.
            let mut purge = lock(&self.last_purge);
            if now_ms.saturating_sub(*purge) >= 1000 {
                *purge = now_ms;
                let window = self.window_ms;
                map.retain(|_, (start, _)| now_ms.saturating_sub(*start) < window);
            }
            if map.len() >= MAX_WINDOW_KEYS {
                // Still full: every untracked key shares one overflow bucket, so the table stays
                // bounded and the aggregate rate of unknown clients is still capped (at a
                // generous multiple of one client's limit).
                let limit = self.limit.saturating_mul(OVERFLOW_FACTOR);
                let e = map.entry(OVERFLOW_KEY.to_string()).or_insert((now_ms, 0));
                if now_ms.saturating_sub(e.0) >= self.window_ms {
                    *e = (now_ms, 0);
                }
                e.1 = e.1.saturating_add(1);
                return e.1 <= limit;
            }
        }
        let e = match map.get_mut(key) {
            Some(e) => e,
            None => map.entry(key.to_string()).or_insert((now_ms, 0)),
        };
        if now_ms.saturating_sub(e.0) >= self.window_ms {
            *e = (now_ms, 0);
        }
        e.1 += 1;
        e.1 <= self.limit
    }

    /// Drop keys whose window started more than `idle_ms` ago.
    pub fn evict(&self, idle_ms: u64, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(idle_ms);
        lock(&self.entries).retain(|_, (start, _)| *start >= cutoff);
    }

    pub fn len(&self) -> usize {
        lock(&self.entries).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A counting semaphore that never blocks. A max of 0 is unlimited.
#[derive(Debug)]
pub struct Semaphore {
    current: AtomicI64,
    max: i64,
}

impl Semaphore {
    pub fn new(max: u32) -> Semaphore {
        Semaphore {
            current: AtomicI64::new(0),
            max: i64::from(max),
        }
    }

    pub fn try_acquire(&self) -> bool {
        if self.max <= 0 {
            return true;
        }
        let mut cur = self.current.load(Ordering::Relaxed);
        loop {
            if cur >= self.max {
                return false;
            }
            match self.current.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(seen) => cur = seen,
            }
        }
    }

    pub fn release(&self) {
        if self.max > 0 {
            self.current.fetch_sub(1, Ordering::AcqRel);
        }
    }

    pub fn value(&self) -> i64 {
        self.current.load(Ordering::Relaxed)
    }
}

/// Per-key bandwidth: a virtual clock per key advances by `bytes / rate`, and a one-second burst is
/// free. `charge` returns how many milliseconds the caller should pause (0 = none).
#[derive(Debug)]
pub struct Bandwidth {
    bytes_per_second: u64,
    buckets: Mutex<HashMap<String, (u64, u64)>>, // key -> (next_us, last_seen_ms)
    overflow: Mutex<(u64, u64)>,
    last_warning: AtomicU64,
}

impl Bandwidth {
    pub fn new(bytes_per_second: u64) -> Option<Bandwidth> {
        (bytes_per_second > 0).then(|| Bandwidth {
            bytes_per_second,
            buckets: Mutex::new(HashMap::new()),
            overflow: Mutex::new((0, 0)),
            last_warning: AtomicU64::new(0),
        })
    }

    pub fn charge(&self, key: &str, bytes: usize, now_ms: u64) -> u64 {
        if bytes == 0 {
            return 0;
        }
        let mut map = lock(&self.buckets);
        if let Some(b) = map.get_mut(key) {
            return self.charge_bucket(b, bytes, now_ms);
        }
        if map.len() >= MAX_BANDWIDTH_KEYS {
            drop(map);
            let last = self.last_warning.load(Ordering::Relaxed);
            if (last == 0 || now_ms.saturating_sub(last - 1) >= 60_000)
                && self
                    .last_warning
                    .compare_exchange(
                        last,
                        now_ms.saturating_add(1),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                crate::log::warn(
                    "bandwidth",
                    format_args!(
                        "source bucket capacity reached; new sources share overflow pacing"
                    ),
                );
            }
            return self.charge_bucket(&mut lock(&self.overflow), bytes, now_ms);
        }
        let b = map.entry(key.to_string()).or_insert((0, now_ms));
        self.charge_bucket(b, bytes, now_ms)
    }

    fn charge_bucket(&self, b: &mut (u64, u64), bytes: usize, now_ms: u64) -> u64 {
        let now_us = now_ms * 1000;
        let cost_us = bytes as u64 * 1_000_000 / self.bytes_per_second;
        let earliest = now_us.saturating_sub(1_000_000);
        let start = b.0.max(earliest);
        let finish = start + cost_us;
        *b = (finish, now_ms);
        if finish <= now_us {
            0
        } else {
            (finish - now_us).div_ceil(1000)
        }
    }

    pub fn evict(&self, idle_ms: u64, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(idle_ms);
        lock(&self.buckets).retain(|_, (_, seen)| *seen >= cutoff);
        let mut overflow = lock(&self.overflow);
        if overflow.1 < cutoff {
            *overflow = (0, now_ms);
        }
    }
}

const SIGDET_RING: usize = 256;

/// The SYN-flood signature: a ring of recent connect outcomes to one destination from one client.
/// It lives inside the connection, so it needs no lock.
#[derive(Debug)]
pub struct SigDet {
    at: [u64; SIGDET_RING],
    ok: [bool; SIGDET_RING],
    head: usize,
    count: usize,
}

impl Default for SigDet {
    fn default() -> Self {
        SigDet {
            at: [0; SIGDET_RING],
            ok: [false; SIGDET_RING],
            head: 0,
            count: 0,
        }
    }
}

impl SigDet {
    pub fn record(&mut self, ok: bool, now_ms: u64, window_ms: u64) {
        self.at[self.head] = now_ms;
        self.ok[self.head] = ok;
        self.head = (self.head + 1) % SIGDET_RING;
        self.count = (self.count + 1).min(SIGDET_RING);
        let cutoff = now_ms.saturating_sub(window_ms);
        while self.count > 0 {
            let tail = (self.head + SIGDET_RING - self.count) % SIGDET_RING;
            if self.at[tail] >= cutoff {
                break;
            }
            self.count -= 1;
        }
    }

    /// When the newest sample was recorded (0 if none).
    pub fn last_seen(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.at[(self.head + SIGDET_RING - 1) % SIGDET_RING]
        }
    }

    /// True when at least `min_samples` are in the window and the failed share is `>= ratio`.
    pub fn matches(&self, min_samples: u32, ratio: f64) -> bool {
        if min_samples == 0 || self.count < min_samples as usize {
            return false;
        }
        let failed = (0..self.count)
            .filter(|i| !self.ok[(self.head + SIGDET_RING - 1 - i) % SIGDET_RING])
            .count();
        failed as f64 / self.count as f64 >= ratio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_counts_per_key_and_resets() {
        let w = Window::new(3, 1000);
        assert!(w.allow("a", 0) && w.allow("a", 10) && w.allow("a", 20));
        assert!(!w.allow("a", 30), "fourth event in the window");
        assert!(w.allow("b", 30), "other keys are separate");
        assert!(w.allow("a", 1000), "a new window starts after window_ms");
        assert_eq!(w.len(), 2);
        w.evict(500, 5000);
        assert!(w.is_empty());
    }

    #[test]
    fn window_with_zero_limit_is_unlimited() {
        let w = Window::new(0, 1000);
        assert!((0..10_000).all(|i| w.allow("a", i)));
    }

    #[test]
    fn semaphore_caps_and_releases() {
        let s = Semaphore::new(2);
        assert!(s.try_acquire() && s.try_acquire());
        assert!(!s.try_acquire());
        s.release();
        assert!(s.try_acquire());
        assert_eq!(s.value(), 2);
        let unlimited = Semaphore::new(0);
        assert!((0..100).all(|_| unlimited.try_acquire()));
    }

    #[test]
    fn bandwidth_gives_a_free_second_then_paces() {
        let b = Bandwidth::new(1000).unwrap(); // 1000 bytes per second
        assert_eq!(b.charge("k", 500, 10_000), 0, "inside the one-second burst");
        assert_eq!(b.charge("k", 500, 10_000), 0);
        let wait = b.charge("k", 1000, 10_000);
        assert!(
            (900..=1100).contains(&wait),
            "paused about a second, got {wait}"
        );
        assert_eq!(b.charge("other", 500, 10_000), 0, "keys are separate");
        assert!(Bandwidth::new(0).is_none());
    }

    #[test]
    fn distinct_sources_cannot_grow_bandwidth_buckets_without_bound() {
        let b = Bandwidth::new(1000).unwrap();
        for i in 0..262_144 + 32 {
            b.charge(&format!("source-{i}"), 1, 10_000);
        }
        let count = lock(&b.buckets).len();
        println!("distinct-source bandwidth buckets: {count}");
        assert!(count <= 262_144);
    }

    #[test]
    fn bandwidth_overflow_is_paced_and_warns_once_per_minute() {
        let b = Bandwidth::new(1000).unwrap();
        for i in 0..MAX_BANDWIDTH_KEYS {
            b.charge(&format!("source-{i}"), 1, 10_000);
        }
        assert_eq!(b.charge("overflow-a", 1000, 10_000), 0);
        assert_eq!(b.charge("overflow-b", 1000, 10_000), 1000);
        assert_eq!(b.last_warning.load(Ordering::Relaxed), 10_001);
        b.charge("overflow-c", 1, 69_999);
        assert_eq!(b.last_warning.load(Ordering::Relaxed), 10_001);
        b.charge("overflow-d", 1, 70_000);
        assert_eq!(b.last_warning.load(Ordering::Relaxed), 70_001);
        assert_eq!(b.charge("source-0", 500, 10_000), 0);
        assert_eq!(lock(&b.buckets).len(), MAX_BANDWIDTH_KEYS);
        b.evict(600_000, 1_000_000);
        assert!(lock(&b.buckets).is_empty());
        assert_eq!(b.charge("fresh", 1000, 1_000_000), 0);
        assert_eq!(lock(&b.buckets).len(), 1);
    }

    #[test]
    fn signature_needs_enough_samples_and_a_high_failure_share() {
        let mut d = SigDet::default();
        for i in 0..10 {
            d.record(false, i, 2000);
        }
        assert!(!d.matches(128, 0.75), "too few samples");
        assert!(d.matches(10, 0.75));
        let mut d = SigDet::default();
        for i in 0..10 {
            d.record(i % 2 == 0, i, 2000);
        }
        assert!(!d.matches(10, 0.75), "half failed is not a flood");
        d.record(false, 5000, 2000);
        assert!(!d.matches(10, 0.0), "old samples aged out of the window");
    }
}
