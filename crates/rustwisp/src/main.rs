//! `rustwisp`: config file and flags in, SIGINT/SIGTERM out.

#[cfg(target_os = "linux")]
fn main() {
    install_panic_hook();
    let code = run();
    rustwisp::log::flush();
    std::process::exit(code);
}

#[cfg(target_os = "linux")]
fn install_panic_hook() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static PANICKING: AtomicBool = AtomicBool::new(false);
    std::panic::set_hook(Box::new(|info| {
        if PANICKING.swap(true, Ordering::SeqCst) {
            std::process::abort();
        }
        rustwisp::log::set_level(rustwisp_config::LogLevel::Error);
        let thread = std::thread::current();
        rustwisp::log::error(
            "panic",
            format_args!(
                "thread {} panicked at {}; terminating",
                thread.name().unwrap_or("unnamed"),
                info.location()
                    .map_or_else(|| "unknown".to_string(), |at| at.to_string())
            ),
        );
        rustwisp::log::flush();
        std::process::abort();
    }));
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    use rustwisp::Server;
    use rustwisp::sys;
    use rustwisp_config::{Parsed, USAGE, VERSION, parse_args};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse_args(&args, |p: &str| std::fs::read_to_string(p)) {
        Ok(Parsed::Run(cfg)) => *cfg,
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return 0;
        }
        Ok(Parsed::Version) => {
            println!("rustwisp {VERSION}");
            return 0;
        }
        Err(e) => {
            eprintln!("rustwisp: {e}");
            eprintln!("try 'rustwisp --help'");
            return 2;
        }
    };
    rustwisp::log::set_level(cfg.log_level);
    let stop_on_stdin_eof = cfg.stop_on_stdin_eof;
    let server = match Server::bind(cfg) {
        Ok(s) => s,
        Err(e) => {
            rustwisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
    let stop_fd = match sys::wake_fd() {
        Ok(fd) => fd,
        Err(e) => {
            rustwisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
    if let Err(e) = sys::install_signal_handlers(&stop_fd) {
        rustwisp::log::error(
            "server",
            format_args!("cannot install signal handlers: {e}"),
        );
        return 1;
    }
    let handle = match server.start() {
        Ok(h) => h,
        Err(e) => {
            rustwisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
    if stop_on_stdin_eof {
        let wake = match stop_fd.try_clone() {
            Ok(fd) => fd,
            Err(e) => {
                rustwisp::log::error("server", format_args!("cannot watch stdin: {e}"));
                handle.stop_and_join();
                return 1;
            }
        };
        if let Err(e) = std::thread::Builder::new()
            .name("stdin".into())
            .spawn(move || {
                use std::io::Read;
                let mut input = std::io::stdin().lock();
                let mut bytes = [0; 256];
                loop {
                    match input.read(&mut bytes) {
                        Ok(0) => {
                            sys::wake(&wake);
                            return;
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => {
                            rustwisp::log::warn("server", format_args!("cannot watch stdin: {e}"));
                            return;
                        }
                    }
                }
            })
        {
            rustwisp::log::error("server", format_args!("cannot watch stdin: {e}"));
            handle.stop_and_join();
            return 1;
        }
    }
    // Block until a signal writes to the eventfd.
    let mut buf = [0u8; 8];
    loop {
        match rustix::io::read(&stop_fd, &mut buf) {
            Ok(_) => break,
            Err(rustix::io::Errno::AGAIN) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => break,
        }
    }
    rustwisp::log::info("server", format_args!("shutting down"));
    handle.stop_and_join();
    0
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rustwisp: the server runs on Linux only");
    std::process::exit(1);
}
