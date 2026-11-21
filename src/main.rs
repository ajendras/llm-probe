use clap::Parser;
use colored::*;
use llm_probe::{run, Cli};
use std::process;

#[tokio::main]
async fn main() {
    // Enable ANSI colors on Windows if needed
    colored::control::set_virtual_terminal(true).ok();

    let cli = Cli::parse();

    if let Err(e) = run(cli.command).await {
        eprintln!("{} Error: {}", "[!]".red().bold(), e);
        process::exit(1);
    }
}
