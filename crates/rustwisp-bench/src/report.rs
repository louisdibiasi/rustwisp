//! Tables, the results file, and comparing two results files.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;

use crate::run::{Kind, Metrics, Options, Results, Scenario};

/// The numbers worth comparing for each kind of scenario: (key, label, higher is better).
fn headline(kind: Kind) -> &'static [(&'static str, &'static str, bool)] {
    match kind {
        Kind::Throughput { .. } => &[
            ("mibs", "MiB/s", true),
            ("mib_per_cpu", "MiB per CPU-s", true),
        ],
        Kind::Rtt { .. } => &[("p50_us", "p50 us", false), ("p999_us", "p99.9 us", false)],
        Kind::Churn => &[("ops_per_s", "streams/s", true)],
    }
}

fn describe(s: &Scenario) -> String {
    match s.kind {
        Kind::Throughput {
            conns,
            streams,
            chunk,
        } => format!(
            "{conns} connection{} x {streams} stream{}, {} KiB packets",
            if conns == 1 { "" } else { "s" },
            if streams == 1 { "" } else { "s" },
            chunk / 1024
        ),
        Kind::Rtt { size } => format!("one {size}-byte message in flight, round trip"),
        Kind::Churn => "open, echo one byte, close; as fast as it goes".to_string(),
    }
}

/// Median, minimum and maximum of one metric over the repetitions.
fn spread(reps: &[Metrics], key: &str) -> Option<(f64, f64, f64)> {
    let mut v: Vec<f64> = reps.iter().filter_map(|m| m.get(key).copied()).collect();
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    let median = if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2.0
    };
    Some((median, v[0], v[v.len() - 1]))
}

fn cell(reps: &[Metrics], key: &str, decimals: usize) -> String {
    spread(reps, key).map_or("-".into(), |(m, _, _)| format!("{m:.decimals$}"))
}

fn ratio(a: Option<f64>, b: Option<f64>) -> String {
    match (a, b) {
        (Some(a), Some(b)) if b > 0.0 => format!("{:.2}x", a / b),
        _ => "-".into(),
    }
}

pub fn print(o: &Options, results: &Results) {
    for scenario in &o.scenarios {
        println!("\n== {}  ({})", scenario.name, describe(scenario));
        let rows: Vec<(&str, &[Metrics])> = o
            .servers
            .iter()
            .map(|s| {
                let reps = results
                    .get(&(scenario.name.to_string(), s.label.clone()))
                    .map_or(&[][..], Vec::as_slice);
                (s.label.as_str(), reps)
            })
            .collect();
        let first = rows.first().map(|r| r.1);
        match scenario.kind {
            Kind::Throughput { .. } => {
                println!(
                    "{:<12} {:>8} {:>13} {:>8} {:>10} {:>9} {:>8} {:>8}   vs first (MiB/s, per CPU)",
                    "server",
                    "MiB/s",
                    "min-max",
                    "CPU s",
                    "MiB/CPU-s",
                    "segs/MiB",
                    "ctx/MiB",
                    "RSS MiB"
                );
                for (label, reps) in &rows {
                    let range = spread(reps, "mibs")
                        .map_or("-".into(), |(_, lo, hi)| format!("{lo:.0}-{hi:.0}"));
                    println!(
                        "{label:<12} {:>8} {:>13} {:>8} {:>10} {:>9} {:>8} {:>8}   {} / {}",
                        cell(reps, "mibs", 0),
                        range,
                        cell(reps, "srv_cpu", 2),
                        cell(reps, "mib_per_cpu", 0),
                        cell(reps, "segs_per_mib", 1),
                        cell(reps, "ctx_per_mib", 2),
                        cell(reps, "rss_mib", 1),
                        ratio(
                            spread(reps, "mibs").map(|s| s.0),
                            first.and_then(|f| spread(f, "mibs")).map(|s| s.0)
                        ),
                        ratio(
                            spread(reps, "mib_per_cpu").map(|s| s.0),
                            first.and_then(|f| spread(f, "mib_per_cpu")).map(|s| s.0)
                        ),
                    );
                }
            }
            Kind::Rtt { .. } => {
                println!(
                    "{:<12} {:>9} {:>9} {:>9} {:>10} {:>8}   vs first (p50, p99.9; below 1 is better)",
                    "server", "p50 us", "p99 us", "p99.9 us", "max us", "RSS MiB"
                );
                for (label, reps) in &rows {
                    println!(
                        "{label:<12} {:>9} {:>9} {:>9} {:>10} {:>8}   {} / {}",
                        cell(reps, "p50_us", 1),
                        cell(reps, "p99_us", 1),
                        cell(reps, "p999_us", 1),
                        cell(reps, "max_us", 0),
                        cell(reps, "rss_mib", 1),
                        ratio(
                            spread(reps, "p50_us").map(|s| s.0),
                            first.and_then(|f| spread(f, "p50_us")).map(|s| s.0)
                        ),
                        ratio(
                            spread(reps, "p999_us").map(|s| s.0),
                            first.and_then(|f| spread(f, "p999_us")).map(|s| s.0)
                        ),
                    );
                }
            }
            Kind::Churn => {
                println!(
                    "{:<12} {:>10} {:>9} {:>8}   vs first",
                    "server", "streams/s", "CPU s", "RSS MiB"
                );
                for (label, reps) in &rows {
                    println!(
                        "{label:<12} {:>10} {:>9} {:>8}   {}",
                        cell(reps, "ops_per_s", 0),
                        cell(reps, "srv_cpu", 2),
                        cell(reps, "rss_mib", 1),
                        ratio(
                            spread(reps, "ops_per_s").map(|s| s.0),
                            first.and_then(|f| spread(f, "ops_per_s")).map(|s| s.0)
                        ),
                    );
                }
            }
        }
        for (label, reps) in &rows {
            if reps.is_empty() {
                println!("{label}: DNF (no repetition finished)");
            }
        }
    }
    println!();
}

/// `server<TAB>scenario<TAB>metric<TAB>median<TAB>min<TAB>max`, one line per number.
pub fn write_tsv(path: &str, results: &Results) -> std::io::Result<()> {
    let mut out = String::from("server\tscenario\tmetric\tmedian\tmin\tmax\n");
    for ((scenario, server), reps) in results {
        let keys: std::collections::BTreeSet<&str> =
            reps.iter().flat_map(|m| m.keys().copied()).collect();
        for key in keys {
            if let Some((m, lo, hi)) = spread(reps, key) {
                let _ = writeln!(out, "{server}\t{scenario}\t{key}\t{m:.4}\t{lo:.4}\t{hi:.4}");
            }
        }
    }
    fs::write(path, out)
}

/// First server in a results file, and its medians keyed by (scenario, metric).
/// Medians keyed by (scenario, metric).
type Medians = BTreeMap<(String, String), f64>;

fn load(path: &str) -> Result<(String, Medians), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut label = String::new();
    let mut map = BTreeMap::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 {
            continue;
        }
        if label.is_empty() {
            label = f[0].to_string();
        }
        if f[0] == label
            && let Ok(v) = f[3].parse::<f64>()
        {
            map.insert((f[1].to_string(), f[2].to_string()), v);
        }
    }
    if map.is_empty() {
        return Err(format!("{path}: no results in it"));
    }
    Ok((label, map))
}

/// Print how the first server in `b` did against the first server in `a`.
pub fn compare(a: &str, b: &str) -> Result<(), String> {
    let (la, ma) = load(a)?;
    let (lb, mb) = load(b)?;
    println!("{lb} ({b}) against {la} ({a})\n");
    println!(
        "{:<14} {:<15} {:>12} {:>12} {:>8}",
        "scenario", "metric", la, lb, "ratio"
    );
    for scenario in crate::run::SCENARIOS {
        for (key, label, higher) in headline(scenario.kind) {
            let k = (scenario.name.to_string(), (*key).to_string());
            if let (Some(x), Some(y)) = (ma.get(&k), mb.get(&k)) {
                let verdict = if (y > x) == *higher {
                    "better"
                } else {
                    "worse"
                };
                println!(
                    "{:<14} {:<15} {x:>12.1} {y:>12.1} {:>7.2}x  {}",
                    scenario.name,
                    label,
                    y / x,
                    if (y - x).abs() / x < 0.08 {
                        "same (inside the noise)"
                    } else {
                        verdict
                    }
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(pairs: &[(&'static str, f64)]) -> Metrics {
        pairs.iter().copied().collect()
    }

    #[test]
    fn the_median_of_odd_and_even_counts() {
        let odd = [rep(&[("x", 3.0)]), rep(&[("x", 1.0)]), rep(&[("x", 2.0)])];
        assert_eq!(spread(&odd, "x"), Some((2.0, 1.0, 3.0)));
        let even = [rep(&[("x", 1.0)]), rep(&[("x", 4.0)])];
        assert_eq!(spread(&even, "x"), Some((2.5, 1.0, 4.0)));
        assert_eq!(spread(&even, "missing"), None);
    }

    #[test]
    fn ratios_guard_against_zero_and_missing() {
        assert_eq!(ratio(Some(3.0), Some(2.0)), "1.50x");
        assert_eq!(ratio(Some(3.0), Some(0.0)), "-");
        assert_eq!(ratio(None, Some(1.0)), "-");
    }

    #[test]
    fn a_results_file_round_trips_through_compare() {
        let mut results = Results::new();
        results.insert(
            ("native-1".into(), "c".into()),
            vec![rep(&[("mibs", 100.0)]), rep(&[("mibs", 120.0)])],
        );
        results.insert(
            ("native-1".into(), "rust".into()),
            vec![rep(&[("mibs", 200.0)])],
        );
        let dir = std::env::temp_dir().join(format!("hw-bench-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.tsv");
        write_tsv(path.to_str().unwrap(), &results).unwrap();
        let (label, medians) = load(path.to_str().unwrap()).unwrap();
        assert_eq!(label, "c");
        assert_eq!(
            medians[&("native-1".to_string(), "mibs".to_string())],
            110.0
        );
        assert!(compare(path.to_str().unwrap(), path.to_str().unwrap()).is_ok());
        assert!(load(dir.join("nope.tsv").to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
