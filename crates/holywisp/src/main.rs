//! `holywisp`: config file and flags in, SIGINT/SIGTERM out.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    use holywisp::Server;
    use holywisp::sys;
    use holywisp_config::{Parsed, USAGE, VERSION, parse_args};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse_args(&args, |p: &str| std::fs::read_to_string(p)) {
        Ok(Parsed::Run(cfg)) => *cfg,
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return 0;
        }
        Ok(Parsed::Version) => {
            println!("holywisp {VERSION}");
            return 0;
        }
        Err(e) => {
            eprintln!("holywisp: {e}");
            eprintln!("try 'holywisp --help'");
            return 2;
        }
    };
    holywisp::log::set_level(cfg.log_level);
    let server = match Server::bind(cfg) {
        Ok(s) => s,
        Err(e) => {
            holywisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
    let stop_fd = match sys::wake_fd() {
        Ok(fd) => fd,
        Err(e) => {
            holywisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
    if let Err(e) = sys::install_signal_handlers(&stop_fd) {
        holywisp::log::error(
            "server",
            format_args!("cannot install signal handlers: {e}"),
        );
        return 1;
    }
    let handle = match server.start() {
        Ok(h) => h,
        Err(e) => {
            holywisp::log::error("server", format_args!("cannot start: {e}"));
            return 1;
        }
    };
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
    holywisp::log::info("server", format_args!("shutting down"));
    handle.stop_and_join();
    0
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("holywisp: the server runs on Linux only");
    std::process::exit(1);
}
