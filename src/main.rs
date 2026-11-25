use clap::Parser;
use colored::*;
use llm_probe::{run, Cli};
use std::process;

/// Enables ANSI escape sequence processing on Windows consoles.
///
/// `colored::control::set_virtual_terminal` only exists on Windows
/// (it is `#[cfg(windows)]` inside the `colored` crate). Other platforms
/// support ANSI colors natively, so this is a no-op there.
#[cfg(windows)]
fn enable_ansi_colors() {
    colored::control::set_virtual_terminal(true).ok();
}

#[cfg(not(windows))]
fn enable_ansi_colors() {}

#[tokio::main]
async fn main() {
    enable_ansi_colors();

    let cli = Cli::parse();

    if let Err(e) = run(cli.command).await {
        eprintln!("{} Error: {}", "[!]".red().bold(), e);
        process::exit(1);
    }
}
