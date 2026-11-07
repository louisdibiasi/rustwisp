//! IP reputation: a 0..100 score per source IP and per destination `ip:port`, raised by weighted
//! events, lowered by decay and persisted as JSON.
//!
//! Tiers turn scores into policy: WARN is only logged, THROTTLE tightens a client's limits, STRICT
//! refuses the client or the destination. The store is a JSON object of our own shape:
//!
//! ```text
//! {"sources":{"<ip>":{"score":N,"firstSeen":MS,"lastSeen":MS,"events":{"<name>":N}}},
//!  "destinations":{"<ip:port>":{...,"distinctSources":N,"seenSources":["<ip>",...]}}}
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use holywisp_config::{REPUTATION_EVENTS, ReputationConfig};

const EVENT_COUNT: usize = REPUTATION_EVENTS.len();
/// A store bigger than this is not read: it is not one of ours.
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 8;
const MAX_SEEN_SOURCES: usize = 256;
/// Entries per table. A table at the cap takes no new keys until old ones decay and are evicted.
const MAX_ENTRIES: usize = 262_144;
/// A destination needs this many distinct sources before a high score can block it for everyone,
/// so one client cannot poison a destination on its own.
const MIN_SOURCES_FOR_STRICT_DEST: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    PrivateEgress = 0,
    SynSignature,
    TwispNoAuth,
    BurstRate,
    SuccessfulStream,
    KnownBadDest,
    AuthFailure,
    ProtocolViolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Normal,
    Warn,
    Throttle,
    Strict,
}

#[derive(Debug, Default, Clone)]
struct Entry {
    score: i32,
    first_seen: i64,
    last_seen: i64,
    events: [u32; EVENT_COUNT],
    seen_sources: HashSet<String>,
}

#[derive(Debug, Default)]
struct Tables {
    sources: HashMap<String, Entry>,
    dests: HashMap<String, Entry>,
    last_decay_ms: u64,
}

#[derive(Debug)]
pub struct Reputation {
    cfg: ReputationConfig,
    source_weights: [i32; EVENT_COUNT],
    dest_weights: [i32; EVENT_COUNT],
    distinct_escalation: i32,
    tables: Mutex<Tables>,
}

/// IPv6 sources are tracked per /64 so rotating addresses inside one network cannot dodge or flood
/// the table. IPv4 and anything unparseable is used as is.
fn source_key(ip: &str) -> String {
    match ip.parse::<std::net::Ipv6Addr>() {
        Ok(v6) if v6.to_ipv4_mapped().is_none() => {
            let mut o = v6.octets();
            o[8..].fill(0);
            format!("{}/64", std::net::Ipv6Addr::from(o))
        }
        _ => ip.to_string(),
    }
}

fn wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn clamp(v: i32) -> i32 {
    v.clamp(0, 100)
}

fn default_weights() -> ([i32; EVENT_COUNT], [i32; EVENT_COUNT]) {
    let mut s = [0; EVENT_COUNT];
    s[Event::PrivateEgress as usize] = 15;
    s[Event::SynSignature as usize] = 25;
    s[Event::TwispNoAuth as usize] = 40;
    s[Event::BurstRate as usize] = 5;
    s[Event::SuccessfulStream as usize] = -2;
    s[Event::KnownBadDest as usize] = 2;
    s[Event::AuthFailure as usize] = 10;
    s[Event::ProtocolViolation as usize] = 5;
    let mut d = [0; EVENT_COUNT];
    d[Event::PrivateEgress as usize] = 20;
    d[Event::SynSignature as usize] = 30;
    d[Event::BurstRate as usize] = 5;
    (s, d)
}

fn apply_overrides(base: &mut [i32; EVENT_COUNT], over: &BTreeMap<String, i32>) {
    for (name, w) in over {
        if let Some(i) = REPUTATION_EVENTS.iter().position(|n| n == name) {
            base[i] = *w;
        }
    }
}

impl Reputation {
    pub fn new(cfg: &ReputationConfig) -> Reputation {
        let (mut sw, mut dw) = default_weights();
        apply_overrides(&mut sw, &cfg.source_weights);
        apply_overrides(&mut dw, &cfg.dest_weights);
        Reputation {
            cfg: cfg.clone(),
            source_weights: sw,
            dest_weights: dw,
            distinct_escalation: 1,
            tables: Mutex::new(Tables::default()),
        }
    }

    fn tables(&self) -> std::sync::MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn add_source(&self, ip: &str, e: Event) {
        let key = source_key(ip);
        let weight = self.source_weights[e as usize];
        let mut t = self.tables();
        // A good deed does not start a record, and a full table takes no new keys.
        if !t.sources.contains_key(&key) && (weight <= 0 || t.sources.len() >= MAX_ENTRIES) {
            return;
        }
        let en = t.sources.entry(key).or_insert_with(|| Entry {
            first_seen: wall_ms(),
            ..Entry::default()
        });
        en.last_seen = wall_ms();
        en.events[e as usize] += 1;
        en.score = clamp(en.score + self.source_weights[e as usize]);
    }

    /// `src_ip` raises the destination further the first time a source is seen for it.
    pub fn add_dest(&self, dest: &str, e: Event, src_ip: Option<&str>) {
        let mut t = self.tables();
        if !t.dests.contains_key(dest)
            && (self.dest_weights[e as usize] <= 0 || t.dests.len() >= MAX_ENTRIES)
        {
            return;
        }
        let en = t.dests.entry(dest.to_string()).or_insert_with(|| Entry {
            first_seen: wall_ms(),
            ..Entry::default()
        });
        en.last_seen = wall_ms();
        en.events[e as usize] += 1;
        en.score = clamp(en.score + self.dest_weights[e as usize]);
        if let Some(ip) = src_ip
            && en.seen_sources.len() < MAX_SEEN_SOURCES
            && en.seen_sources.insert(ip.to_string())
        {
            en.score = clamp(en.score + self.distinct_escalation);
        }
    }

    pub fn source_score(&self, ip: &str) -> i32 {
        self.tables()
            .sources
            .get(&source_key(ip))
            .map_or(0, |e| e.score)
    }

    pub fn dest_score(&self, dest: &str) -> i32 {
        self.tables().dests.get(dest).map_or(0, |e| e.score)
    }

    /// The tier of a destination: STRICT only once enough distinct sources have been seen for it.
    pub fn dest_tier(&self, dest: &str) -> Tier {
        let t = self.tables();
        let Some(e) = t.dests.get(dest) else {
            return Tier::Normal;
        };
        let tier = self.tier(e.score);
        if tier == Tier::Strict && e.seen_sources.len() < MIN_SOURCES_FOR_STRICT_DEST {
            Tier::Throttle
        } else {
            tier
        }
    }

    pub fn tier(&self, score: i32) -> Tier {
        let c = &self.cfg;
        let at = |limit: u32| limit > 0 && score >= limit as i32;
        if at(c.strict) {
            Tier::Strict
        } else if at(c.throttle) {
            Tier::Throttle
        } else if at(c.warn) {
            Tier::Warn
        } else {
            Tier::Normal
        }
    }

    pub fn counts(&self) -> (usize, usize) {
        let t = self.tables();
        (t.sources.len(), t.dests.len())
    }

    /// Lower every score by the time elapsed since the last decay, keeping the remainder.
    pub fn decay(&self, now_ms: u64) {
        let per_hour = u64::from(self.cfg.decay_per_hour);
        if per_hour == 0 {
            return;
        }
        let mut guard = self.tables();
        let t = &mut *guard;
        if t.last_decay_ms == 0 {
            t.last_decay_ms = now_ms;
            return;
        }
        let elapsed = now_ms.saturating_sub(t.last_decay_ms);
        let delta = (per_hour * elapsed / 3_600_000) as i32;
        if delta > 0 {
            for e in t.sources.values_mut().chain(t.dests.values_mut()) {
                e.score = clamp(e.score - delta);
            }
            t.last_decay_ms = now_ms - (elapsed - delta as u64 * 3_600_000 / per_hour);
        }
    }

    /// Drop low scores that have been quiet for `evict-after-days`.
    pub fn evict(&self) {
        let days = i64::from(self.cfg.evict_after_days);
        if days == 0 {
            return;
        }
        let cutoff = wall_ms() - days * 86_400_000;
        let mut t = self.tables();
        t.sources
            .retain(|_, e| !(e.score < 5 && e.last_seen < cutoff));
        t.dests
            .retain(|_, e| !(e.score < 5 && e.last_seen < cutoff));
    }

    // ------------------------------------------------------------------------------ persistence

    /// Write the store (owner-only) via a temporary file and a rename. A no-op without a path.
    pub fn save(&self) -> io::Result<()> {
        let path = self.cfg.store_path.as_str();
        if path.is_empty() {
            return Ok(());
        }
        let json = self.to_json();
        if let Some(dir) = Path::new(path).parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = format!("{path}.tmp");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    }

    /// Read the store. A missing file is fine; a file that is not ours is an error.
    pub fn load(&self) -> io::Result<()> {
        let path = self.cfg.store_path.as_str();
        if path.is_empty() {
            return Ok(());
        }
        let text = match std::fs::read(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        if text.len() > MAX_STORE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "store too large",
            ));
        }
        let text = String::from_utf8(text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "store is not UTF-8"))?;
        self.merge_json(&text)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn to_json(&self) -> String {
        fn table(out: &mut String, map: &HashMap<String, Entry>, dest: bool) {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.into_iter().enumerate() {
                let e = &map[k];
                if i > 0 {
                    out.push(',');
                }
                json::string(out, k);
                out.push_str(&format!(
                    ":{{\"score\":{},\"firstSeen\":{},\"lastSeen\":{},\"events\":{{",
                    e.score, e.first_seen, e.last_seen
                ));
                let mut first = true;
                for (n, name) in REPUTATION_EVENTS.iter().enumerate() {
                    if e.events[n] > 0 {
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        out.push_str(&format!("\"{name}\":{}", e.events[n]));
                    }
                }
                out.push('}');
                if dest {
                    out.push_str(&format!(
                        ",\"distinctSources\":{},\"seenSources\":[",
                        e.seen_sources.len()
                    ));
                    let mut seen: Vec<&String> = e.seen_sources.iter().collect();
                    seen.sort();
                    for (j, s) in seen.into_iter().enumerate() {
                        if j > 0 {
                            out.push(',');
                        }
                        json::string(out, s);
                    }
                    out.push(']');
                }
                out.push('}');
            }
        }
        let t = self.tables();
        let mut out = String::from("{\"sources\":{");
        table(&mut out, &t.sources, false);
        out.push_str("},\"destinations\":{");
        table(&mut out, &t.dests, true);
        out.push_str("}}\n");
        out
    }

    fn merge_json(&self, text: &str) -> Result<(), String> {
        let root = json::parse(text)?;
        let obj = root.as_object().ok_or("store is not an object")?;
        let mut t = self.tables();
        for (section, dest) in [("sources", false), ("destinations", true)] {
            let Some(entries) = obj.get(section).and_then(json::Value::as_object) else {
                continue;
            };
            for (key, v) in entries {
                let Some(o) = v.as_object() else { continue };
                let num = |k: &str| o.get(k).and_then(json::Value::as_i64).unwrap_or(0);
                let mut e = Entry {
                    score: clamp(num("score") as i32),
                    first_seen: num("firstSeen"),
                    last_seen: num("lastSeen"),
                    ..Entry::default()
                };
                if let Some(ev) = o.get("events").and_then(json::Value::as_object) {
                    for (n, name) in REPUTATION_EVENTS.iter().enumerate() {
                        e.events[n] = ev
                            .get(*name)
                            .and_then(json::Value::as_i64)
                            .unwrap_or(0)
                            .max(0) as u32;
                    }
                }
                if dest && let Some(list) = o.get("seenSources").and_then(json::Value::as_array) {
                    for s in list
                        .iter()
                        .filter_map(json::Value::as_str)
                        .take(MAX_SEEN_SOURCES)
                    {
                        e.seen_sources.insert(s.to_string());
                    }
                }
                let map = if dest { &mut t.dests } else { &mut t.sources };
                map.insert(key.clone(), e);
            }
        }
        Ok(())
    }
}

/// A JSON reader for the store: objects, arrays, strings and integers, bounded in depth.
mod json {
    use std::collections::HashMap;

    pub enum Value {
        Object(HashMap<String, Value>),
        Array(Vec<Value>),
        Str(String),
        Int(i64),
        Other,
    }

    impl Value {
        pub fn as_object(&self) -> Option<&HashMap<String, Value>> {
            match self {
                Value::Object(o) => Some(o),
                _ => None,
            }
        }
        pub fn as_array(&self) -> Option<&Vec<Value>> {
            match self {
                Value::Array(a) => Some(a),
                _ => None,
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            match self {
                Value::Str(s) => Some(s),
                _ => None,
            }
        }
        pub fn as_i64(&self) -> Option<i64> {
            match self {
                Value::Int(n) => Some(*n),
                _ => None,
            }
        }
    }

    pub fn string(out: &mut String, s: &str) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    struct P<'a> {
        b: &'a [u8],
        i: usize,
    }

    pub fn parse(text: &str) -> Result<Value, String> {
        let mut p = P {
            b: text.as_bytes(),
            i: 0,
        };
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err("trailing data after the store".into());
        }
        Ok(v)
    }

    impl P<'_> {
        fn ws(&mut self) {
            while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
                self.i += 1;
            }
        }

        fn eat(&mut self, c: u8) -> Result<(), String> {
            self.ws();
            if self.b.get(self.i) == Some(&c) {
                self.i += 1;
                Ok(())
            } else {
                Err(format!("expected '{}' at byte {}", c as char, self.i))
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, String> {
            if depth > super::MAX_JSON_DEPTH {
                return Err("store nested too deeply".into());
            }
            self.ws();
            match self.b.get(self.i) {
                Some(b'{') => {
                    self.i += 1;
                    let mut map = HashMap::new();
                    self.ws();
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Ok(Value::Object(map));
                    }
                    loop {
                        self.ws();
                        let k = self.str()?;
                        self.eat(b':')?;
                        let v = self.value(depth + 1)?;
                        map.insert(k, v);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                return Ok(Value::Object(map));
                            }
                            _ => return Err(format!("bad object at byte {}", self.i)),
                        }
                    }
                }
                Some(b'[') => {
                    self.i += 1;
                    let mut list = Vec::new();
                    self.ws();
                    if self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Ok(Value::Array(list));
                    }
                    loop {
                        list.push(self.value(depth + 1)?);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                return Ok(Value::Array(list));
                            }
                            _ => return Err(format!("bad array at byte {}", self.i)),
                        }
                    }
                }
                Some(b'"') => Ok(Value::Str(self.str()?)),
                Some(c) if c.is_ascii_digit() || *c == b'-' => {
                    let start = self.i;
                    self.i += 1;
                    while self.i < self.b.len()
                        && matches!(
                            self.b[self.i],
                            b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'
                        )
                    {
                        self.i += 1;
                    }
                    let s = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("");
                    Ok(s.parse::<i64>().map_or(Value::Other, Value::Int))
                }
                Some(_) => {
                    for lit in ["true", "false", "null"] {
                        if self.b[self.i..].starts_with(lit.as_bytes()) {
                            self.i += lit.len();
                            return Ok(Value::Other);
                        }
                    }
                    Err(format!("unexpected byte at {}", self.i))
                }
                None => Err("unexpected end of store".into()),
            }
        }

        fn str(&mut self) -> Result<String, String> {
            if self.b.get(self.i) != Some(&b'"') {
                return Err(format!("expected a string at byte {}", self.i));
            }
            self.i += 1;
            let mut out = Vec::new();
            while let Some(&c) = self.b.get(self.i) {
                self.i += 1;
                match c {
                    b'"' => {
                        return String::from_utf8(out).map_err(|_| "bad UTF-8 in string".into());
                    }
                    b'\\' => {
                        let e = *self.b.get(self.i).ok_or("bad escape")?;
                        self.i += 1;
                        match e {
                            b'"' | b'\\' | b'/' => out.push(e),
                            b'n' => out.push(b'\n'),
                            b't' => out.push(b'\t'),
                            b'r' => out.push(b'\r'),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'u' => {
                                let hex = self.b.get(self.i..self.i + 4).ok_or("bad \\u escape")?;
                                let cp =
                                    u32::from_str_radix(std::str::from_utf8(hex).unwrap_or(""), 16)
                                        .map_err(|_| "bad \\u escape")?;
                                self.i += 4;
                                let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                                let mut buf = [0u8; 4];
                                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                            }
                            _ => return Err("unknown escape".into()),
                        }
                    }
                    c => out.push(c),
                }
            }
            Err("unterminated string".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ReputationConfig {
        ReputationConfig {
            store_path: String::new(),
            ..holywisp_config::Config::default().reputation
        }
    }

    #[test]
    fn events_move_scores_within_bounds_and_cross_tiers() {
        let r = Reputation::new(&cfg());
        assert_eq!(r.tier(r.source_score("1.2.3.4")), Tier::Normal);
        for _ in 0..3 {
            r.add_source("1.2.3.4", Event::SynSignature); // +25 each
        }
        assert_eq!(r.source_score("1.2.3.4"), 75);
        assert_eq!(r.tier(75), Tier::Throttle);
        r.add_source("1.2.3.4", Event::SynSignature);
        assert_eq!(r.tier(r.source_score("1.2.3.4")), Tier::Strict);
        for _ in 0..10 {
            r.add_source("1.2.3.4", Event::SynSignature);
        }
        assert_eq!(r.source_score("1.2.3.4"), 100, "clamped");
        r.add_source("5.6.7.8", Event::SuccessfulStream);
        assert_eq!(r.source_score("5.6.7.8"), 0, "never below zero");
    }

    #[test]
    fn weight_overrides_apply() {
        let mut c = cfg();
        c.source_weights.insert("burstRate".into(), 50);
        let r = Reputation::new(&c);
        r.add_source("a", Event::BurstRate);
        assert_eq!(r.source_score("a"), 50);
    }

    #[test]
    fn destinations_escalate_per_new_source_only() {
        let r = Reputation::new(&cfg());
        r.add_dest("9.9.9.9:80", Event::BurstRate, Some("1.1.1.1")); // 5 + 1
        r.add_dest("9.9.9.9:80", Event::BurstRate, Some("1.1.1.1")); // +5
        r.add_dest("9.9.9.9:80", Event::BurstRate, Some("2.2.2.2")); // +5 +1
        assert_eq!(r.dest_score("9.9.9.9:80"), 17);
    }

    #[test]
    fn one_source_cannot_make_a_destination_strict_alone() {
        let r = Reputation::new(&cfg());
        for _ in 0..40 {
            r.add_dest("9.9.9.9:80", Event::SynSignature, Some("1.1.1.1"));
        }
        assert_eq!(r.dest_score("9.9.9.9:80"), 100);
        assert_eq!(r.dest_tier("9.9.9.9:80"), Tier::Throttle);
        r.add_dest("9.9.9.9:80", Event::BurstRate, Some("2.2.2.2"));
        r.add_dest("9.9.9.9:80", Event::BurstRate, Some("3.3.3.3"));
        assert_eq!(r.dest_tier("9.9.9.9:80"), Tier::Strict);
    }

    #[test]
    fn ipv6_sources_share_a_record_per_slash_64_and_good_deeds_start_none() {
        let r = Reputation::new(&cfg());
        r.add_source("2001:db8:1:2::1", Event::BurstRate);
        r.add_source("2001:db8:1:2:ffff::9", Event::BurstRate);
        assert_eq!(r.source_score("2001:db8:1:2::77"), 10);
        assert_eq!(r.source_score("2001:db8:1:3::1"), 0);
        r.add_source("203.0.113.1", Event::SuccessfulStream);
        assert_eq!(
            r.counts().0,
            1,
            "a successful stream alone creates no entry"
        );
    }

    #[test]
    fn decay_is_proportional_and_keeps_the_remainder() {
        let mut c = cfg();
        c.decay_per_hour = 10;
        let r = Reputation::new(&c);
        r.add_source("a", Event::SynSignature);
        r.add_source("a", Event::SynSignature); // 50
        r.decay(1_000);
        r.decay(1_000 + 3_600_000); // one hour: -10
        assert_eq!(r.source_score("a"), 40);
        r.decay(1_000 + 3_600_000 + 1_800_000); // half an hour is 5 points
        assert_eq!(r.source_score("a"), 35);
    }

    #[test]
    fn the_store_roundtrips_through_a_file_with_owner_only_access() {
        let dir = std::env::temp_dir().join(format!("hw-rep-{}", std::process::id()));
        let path = dir.join("rep.json");
        let c = ReputationConfig {
            store_path: path.to_string_lossy().into_owned(),
            ..cfg()
        };
        let r = Reputation::new(&c);
        r.add_source("203.0.113.5", Event::AuthFailure);
        r.add_dest("198.51.100.1:443", Event::SynSignature, Some("203.0.113.5"));
        r.save().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let again = Reputation::new(&c);
        again.load().unwrap();
        assert_eq!(again.source_score("203.0.113.5"), 10);
        assert_eq!(again.dest_score("198.51.100.1:443"), 31);
        assert_eq!(again.counts(), (1, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_store_is_fine_and_a_foreign_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("hw-rep-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rep.json");
        let c = ReputationConfig {
            store_path: path.to_string_lossy().into_owned(),
            ..cfg()
        };
        let r = Reputation::new(&c);
        assert!(r.load().is_ok());
        std::fs::write(&path, "[1,2,3]").unwrap();
        assert!(r.load().is_err());
        std::fs::write(&path, "{\"sources\":{\"a\":{\"score\":").unwrap();
        assert!(r.load().is_err());
        let deep = "[".repeat(100);
        std::fs::write(&path, deep).unwrap();
        assert!(
            r.load().is_err(),
            "deep nesting is refused, not recursed into"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn json_strings_are_escaped_and_read_back() {
        let r = Reputation::new(&cfg());
        r.add_source("we\"ird\\key\n", Event::BurstRate);
        let j = r.to_json();
        let again = Reputation::new(&cfg());
        again.merge_json(&j).unwrap();
        assert_eq!(again.source_score("we\"ird\\key\n"), 5);
    }
}
