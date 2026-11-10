use rustwisp_config::LogLevel;
use std::fmt::{self, Write as _};
use std::io::Write as _;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::time::{SystemTime, UNIX_EPOCH};

static LEVEL: AtomicU8 = AtomicU8::new(1);
static SINK: OnceLock<Option<SyncSender<Event>>> = OnceLock::new();

#[derive(Debug)]
enum Event {
    Line(String),
    Flush(SyncSender<()>),
}

fn sink() -> Option<&'static SyncSender<Event>> {
    SINK.get_or_init(|| {
        let (tx, rx) = sync_channel::<Event>(256);
        std::thread::Builder::new()
            .name("rustwisp-log".into())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    match event {
                        Event::Line(line) => {
                            let _ = std::io::stderr().lock().write(line.as_bytes());
                        }
                        Event::Flush(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .ok()
            .map(|_| tx)
    })
    .as_ref()
}

pub fn set_level(level: LogLevel) {
    LEVEL.store(
        match level {
            LogLevel::Debug => 0,
            LogLevel::Info => 1,
            LogLevel::Warn => 2,
            LogLevel::Error => 3,
            LogLevel::None => 4,
        },
        Ordering::Relaxed,
    );
}

fn timestamp(ms: u128) -> String {
    let seconds = (ms / 1000) as i64;
    let z = seconds / 86400 + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60,
        ms % 1000
    )
}

struct Line(String);
impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            if self.0.len() + ch.len_utf8() > 1022 {
                break;
            }
            self.0.push(if ch.is_control() { ' ' } else { ch });
        }
        Ok(())
    }
}

fn emit(level: u8, tag: &str, args: fmt::Arguments<'_>) {
    if level < LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let mut line = Line(String::with_capacity(1024));
    let _ = write!(
        line,
        "{} [{}] {tag}: {args}",
        timestamp(now),
        ["debug", "info", "warn", "error"][level as usize]
    );
    line.0.push('\n');
    if let Some(sink) = sink() {
        let _ = sink.try_send(Event::Line(line.0));
    }
}

/// A blocked sink must not delay process shutdown indefinitely.
pub fn flush() {
    if let Some(Some(sink)) = SINK.get() {
        let (tx, rx) = sync_channel(0);
        if sink.try_send(Event::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(std::time::Duration::from_millis(100));
        }
    }
}

pub fn debug(tag: &str, args: fmt::Arguments<'_>) {
    emit(0, tag, args);
}
pub fn info(tag: &str, args: fmt::Arguments<'_>) {
    emit(1, tag, args);
}
pub fn warn(tag: &str, args: fmt::Arguments<'_>) {
    emit(2, tag, args);
}
pub fn error(tag: &str, args: fmt::Arguments<'_>) {
    emit(3, tag, args);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_dates_and_bounded_lines() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(timestamp(951782400123), "2000-02-29T00:00:00.123Z");
        let mut line = Line(String::new());
        write!(line, "a\nb{}", "\u{e9}".repeat(2000)).unwrap();
        assert!(!line.0.contains('\n'));
        assert!(line.0.len() <= 1022);
        let controls: String = (0..=159)
            .filter_map(char::from_u32)
            .filter(|ch| ch.is_control())
            .collect();
        let mut line = Line(String::new());
        write!(line, "before{controls}after").unwrap();
        assert!(line.0.chars().all(|ch| !ch.is_control()));
    }
}
