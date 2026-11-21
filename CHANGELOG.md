# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-21

### Added

- Attack Library — 20 built-in templates covering prompt injection, DAN-style jailbreaks, encoding tricks and PII extraction.
- Risk Scoring — Heuristic plus optional LLM-as-judge scoring that quantifies success rate per attack vector.
- Model Agnostic — Talks to Ollama, vLLM, OpenAI-compatible APIs or any HTTP endpoint using a simple client trait.
- Terminal Reports — Live progress, color-coded vulnerability tables and one-click JSON export for CI.
- Parallel Runs — Runs multiple attacks concurrently with Tokio and aggregates results across models.
- Custom Attacks — Load YAML attack templates or extend via the Attack trait with zero boilerplate.
- Session Replay — Saves every prompt/response pair so you can replay and debug failing cases later.
- Trend Tracking — Stores historical scan results so you can watch robustness improve over model updates.
