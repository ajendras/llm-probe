use llm_probe::{attack::load_attacks_from_yaml, attacks, RedTeamer};
use std::path::Path;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Use built-in attacks by default. If a user-provided attacks.yaml exists,
    // load it instead so no Rust code is required to define new attacks.
    let attacks = if Path::new("attacks.yaml").exists() {
        load_attacks_from_yaml("attacks.yaml")?
    } else {
        attacks::all_attacks()
    };

    let report = RedTeamer::builder()
        .attacks(attacks)
        .build()
        .run("llama3.1")
        .await?;

    println!("Risk level: {} (avg score {:.2})", 
             report.summary.risk_level, report.summary.average_score);
    Ok(())
}
