# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] - 2026-10-15

### Added

- Baseline mode: `core/baseline.py` learning engine + `baseline_check.py` headless CLI. Learns normal processes and remote connection targets, flags unseen entities once history threshold is met, JSON findings output for cron/CI (exit 1 on anomalies)
- `config/baseline.yaml.example` configuration reference
- Baseline unit tests (7 new)

### Removed

- `SQSM Banner.html` (pre-rename leftover, unreferenced in code)

## [1.0.0] - 2026-08-29

### Added

- Live-response endpoint monitoring for Windows: watches processes, connections, and persistence
- VirusTotal and AbuseIPDB enrichment for indicators
- Plain-English LLM alerts
- MIT license
