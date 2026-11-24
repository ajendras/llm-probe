use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Configuration for LLM Probe, deserialized from a TOML file.
///
/// Contains settings for model selection, endpoint, timeouts, concurrency,
/// and output paths. Falls back to secure, reasonable defaults when no
/// configuration file is present.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Target model name (e.g. "llama3.1", "mistral-7b").
    #[serde(default = "default_model")]
    pub model: String,

    /// Optional custom HTTP endpoint. When set, clients will target this
    /// URL instead of built-in defaults.
    #[serde(default)]
    pub endpoint: Option<String>,

    /// HTTP request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// Maximum number of concurrent attacks (Tokio tasks).
    #[serde(default = "default_concurrency")]
    pub concurrency: u8,

    /// Optional path to write the full JSON report and session replay.
    #[serde(default)]
    pub output: Option<String>,

    /// Optional API key for authenticated endpoints (OpenAI-compatible).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Optional path to a YAML file containing custom attack definitions.
    /// When present these attacks replace the built-in set.
    #[serde(default)]
    pub attacks_yaml: Option<String>,
}

fn default_model() -> String {
    "llama3.1".to_string()
}

fn default_timeout() -> u64 {
    60
}

fn default_concurrency() -> u8 {
    4
}

impl Default for Config {
    fn default() -> Self {
        Self {
            model: default_model(),
            endpoint: None,
            timeout: default_timeout(),
            concurrency: default_concurrency(),
            output: None,
            api_key: None,
            attacks_yaml: None,
        }
    }
}

/// Loads configuration from `llm-probe.toml` in the current working directory.
/// If the file does not exist, returns the default configuration.
///
/// # Errors
///
/// Returns an error if the TOML file exists but cannot be read or parsed.
pub fn load_config() -> Result<Config> {
    let config_path = Path::new("llm-probe.toml");

    if config_path.exists() {
        let content = std::fs::read_to_string(config_path)
            .context("Failed to read llm-probe.toml")?;
        let config: Config = toml::from_str(&content)
            .context("Failed to parse llm-probe.toml — check syntax")?;
        Ok(config)
    } else {
        Ok(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_are_secure_and_sensible() {
        let cfg = Config::default();
        assert_eq!(cfg.model, "llama3.1");
        assert_eq!(cfg.timeout, 60);
        assert_eq!(cfg.concurrency, 4);
        assert!(cfg.endpoint.is_none());
        assert!(cfg.api_key.is_none());
        assert!(cfg.attacks_yaml.is_none());
    }

    #[test]
    fn test_load_config_falls_back_to_default_when_no_file() {
        // We cannot easily delete files in test, but we can test that the
        // function does not panic when file is absent.
        let result = load_config();
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert_eq!(cfg.model, "llama3.1");
    }
}
