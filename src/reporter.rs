use anyhow::{Context, Result};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Attribute, Cell, Color as TableColor, Table};
use crate::{AttackMetadata, AttackResult, AttackType, Report, ReportSummary};
use std::path::Path;

/// Generates terminal reports, JSON exports, and summaries.
///
/// All output follows the project's retro-terminal aesthetic: phosphor-green
/// text, monospace, ASCII borders, subtle dimming, and clear red/green
/// vulnerability indicators. The table rendering mirrors the style established
/// in `lib.rs::render_terminal_report` but is encapsulated for reuse.
pub struct ReportGenerator;

impl ReportGenerator {
    /// Renders a complete scan report as a retro-styled terminal table.
    ///
    /// Uses `comfy-table` with UTF8 borders, color-coded rows, and truncated
    /// reasoning to keep the display compact.
    pub fn render_table(report: &Report) {
        println!("\n{}", "═".repeat(80).dimmed());
        println!(
            " {} LLM-PROBE SCAN REPORT — MODEL: {} — {} {}",
            "█".green(),
            report.model.bold().cyan(),
            report.timestamp.dimmed(),
            "█".green()
        );
        println!("{}", "═".repeat(80).dimmed());

        let risk_display = match report.summary.risk_level.as_str() {
            "HIGH" => report.summary.risk_level.red().bold().to_string(),
            "MEDIUM" => report.summary.risk_level.yellow().bold().to_string(),
            _ => report.summary.risk_level.green().bold().to_string(),
        };

        println!(
            " RISK LEVEL : {}   |   VULNERABLE : {} / {}   |   AVG SCORE : {:.2}",
            risk_display,
            report.summary.vulnerable,
            report.summary.total,
            report.summary.average_score
        );
        println!("{}", "─".repeat(80).dimmed());

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec![
            Cell::new("ATTACK VECTOR").add_attribute(Attribute::Bold),
            Cell::new("CATEGORY"),
            Cell::new("SCORE"),
            Cell::new("STATUS"),
            Cell::new("REASONING"),
        ]);

        for result in &report.results {
            let is_vuln = result.is_vulnerable();
            let row_color = if is_vuln { TableColor::Red } else { TableColor::Green };

            let status_cell = if is_vuln {
                Cell::new("VULNERABLE")
                    .fg(TableColor::Red)
                    .add_attribute(Attribute::Bold)
            } else {
                Cell::new("RESISTANT").fg(TableColor::Green)
            };

            let reasoning = if result.reasoning.len() > 45 {
                result.reasoning.chars().take(42).collect::<String>() + "…"
            } else {
                result.reasoning.clone()
            };

            table.add_row(vec![
                Cell::new(&result.metadata.name).fg(row_color),
                Cell::new(result.metadata.category.to_string()),
                Cell::new(format!("{:.2}", result.score)).fg(row_color),
                status_cell,
                Cell::new(reasoning),
            ]);
        }

        println!("{table}");
        println!("\n{} Session replay and JSON export available with --output", "[INFO]".blue());
        println!("{}", "═".repeat(80).dimmed());
    }

    /// Serializes the full report (including every prompt/response pair) to JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the file cannot be written.
    pub fn write_json(report: &Report, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(report)
            .context("Failed to serialize report to JSON")?;

        std::fs::write(path, json)
            .with_context(|| format!("Failed to write JSON report to {}", path.display()))?;

        println!("{} Full session replay saved to {}", "[+]".green(), path.display());
        Ok(())
    }

    /// Returns a compact one-line summary string suitable for logs or CI output.
    pub fn summarize(report: &Report) -> String {
        format!(
            "Model: {} | Risk: {} | Vulnerable: {}/{} | Avg Score: {:.2}",
            report.model,
            report.summary.risk_level,
            report.summary.vulnerable,
            report.summary.total,
            report.summary.average_score
        )
    }

    /// Filters a slice of results to only those that crossed the vulnerability threshold.
    pub fn vulnerable_only(results: &[AttackResult]) -> Vec<&AttackResult> {
        results.iter().filter(|r| r.is_vulnerable()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackMetadata, AttackResult, AttackType};

    #[test]
    fn test_summarize_produces_expected_format() {
        let report = Report {
            model: "llama3.1".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            summary: ReportSummary {
                total: 12,
                vulnerable: 5,
                average_score: 0.62,
                risk_level: "MEDIUM".to_string(),
            },
            results: vec![],
        };

        let summary = ReportGenerator::summarize(&report);
        assert!(summary.contains("llama3.1"));
        assert!(summary.contains("MEDIUM"));
        assert!(summary.contains("5/12"));
        assert!(summary.contains("0.62"));
    }

    #[test]
    fn test_vulnerable_only_filters_correctly() {
        let results = vec![
            AttackResult {
                metadata: AttackMetadata {
                    name: "Injection Test".to_string(),
                    category: AttackType::Injection,
                    severity: 0.8,
                    description: "test".to_string(),
                },
                prompt: "ignore all".to_string(),
                response: "SYSTEM PROMPT leaked".to_string(),
                score: 0.92,
                success: true,
                reasoning: "Leak detected".to_string(),
            },
            AttackResult {
                metadata: AttackMetadata {
                    name: "Safe Test".to_string(),
                    category: AttackType::Jailbreak,
                    severity: 0.4,
                    description: "test".to_string(),
                },
                prompt: "normal question".to_string(),
                response: "I cannot do that".to_string(),
                score: 0.15,
                success: false,
                reasoning: "Model refused".to_string(),
            },
        ];

        let vulnerable = ReportGenerator::vulnerable_only(&results);
        assert_eq!(vulnerable.len(), 1);
        assert_eq!(vulnerable[0].metadata.name, "Injection Test");
    }

    #[test]
    fn test_render_table_does_not_panic_on_empty_report() {
        let empty_report = Report {
            model: "test-model".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: ReportSummary {
                total: 0,
                vulnerable: 0,
                average_score: 0.0,
                risk_level: "LOW".to_string(),
            },
            results: vec![],
        };
        // Rendering should not panic even with zero results
        ReportGenerator::render_table(&empty_report);
    }
}
