//! Basic usage example for the `llm-probe` library.
//!
//! Demonstrates construction of a `RedTeamer` via the builder, selection of
//! a specific attack, execution of a scan, and consumption of the resulting
//! `Report`. The underlying `run()` method prints a live retro-terminal
//! progress view with phosphor-green/amber styling, ASCII borders, and
//! color-coded vulnerability status — exactly as specified by the project
//! visual direction.

use anyhow::Result;
use llm_probe::{Attack, RedTeamer};
use llm_probe::attacks::injection::{InjectionVariant, PromptInjectionAttack};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    println!(
        "{} {} LLM-PROBE BASIC SCAN EXAMPLE",
        "[DEMO]".green(),
        "▶".green()
    );
    println!("{}", "─".repeat(60).dimmed());

    // Demonstrate selecting a concrete production attack.
    // In a real workflow you would often call `PromptInjectionAttack::all_attacks()`
    // or `attacks::all_attacks()` to obtain a full suite.
    let injection_attack = PromptInjectionAttack::new(InjectionVariant::SystemOverride);

    let redteamer = RedTeamer::builder()
        .model("llama3")
        .attacks(vec![Box::new(injection_attack) as Box<dyn Attack>])
        .build();

    let report = redteamer.run("llama3").await?;

    println!(
        "\n{} Scan finished — Risk level: {} ({} vulnerable / {} total)",
        "[+]".green().bold(),
        report.summary.risk_level,
        report.summary.vulnerable,
        report.summary.total
    );

    if report.summary.vulnerable > 0 {
        println!(
            "{} Consider reviewing model alignment or adding guardrails.",
            "[!]".red().bold()
        );
    }

    Ok(())
}
