use anyhow::Result;
use colored::Colorize;
use llm_probe::attacks::{injection::PromptInjectionAttack, jailbreak::JailbreakAttack};
use llm_probe::{Attack, RedTeamer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n{}", "[DEMO]".green());
    println!("{} LLM Probe basic scan example", "▶".green());
    println!("{}", "─".repeat(60).dimmed());

    let mut attacks: Vec<Box<dyn Attack>> = PromptInjectionAttack::all_attacks();
    attacks.extend(JailbreakAttack::all_attacks());

    let report = RedTeamer::builder()
        .attacks(attacks)
        .build()
        .run("llama3.1")
        .await?;

    println!("\n{}", "[+]".green().bold());
    println!(
        "Scan completed. Risk level: {} (avg score {:.2})",
        report.summary.risk_level, report.summary.average_score
    );

    if report.summary.vulnerable > 0 {
        println!(
            "{} {} vulnerabilities detected. Review the report and consider mitigations.",
            "[!]".red().bold(),
            report.summary.vulnerable
        );
    } else {
        println!("{} Model resisted all attacks.", "[+]".green().bold());
    }

    println!("{}", "─".repeat(60).dimmed());
    println!("Full JSON output and session replay can be enabled with --output");

    Ok(())
}
