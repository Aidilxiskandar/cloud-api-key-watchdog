# Changelog

## [1.1.0] - 2026-05-14

### Changed
- Dashboard is now cloud-hosted — no local Flask setup required
- Each user gets a private dashboard view via their unique machine ID
- Default `dashboardUrl` points to the live Railway deployment

## [1.0.0] - 2026-05-07

### Added
- Save-time secret detection using regex patterns (AWS, GitHub, Google, Stripe, Slack, Private Keys, Generic API Keys)
- Shannon entropy detection for unstructured high-entropy secrets (threshold: 4.5 bits)
- Modal dialog on detection: Block Save / Save Anyway / Show Details
- Block Save preserves editor edits — file on disk stays clean, unsaved changes restored automatically
- QuickPick findings list showing line, column, detection method, and matched text per finding
- BLOCKED vs BYPASSED status tracking
- Flask monitoring dashboard with real-time charts and detection history
- Manual repository scanner supporting GitHub URLs and file/ZIP uploads
- Status bar button to open the dashboard
- Output channel logging all detection events
- `API Key Watchdog: Scan Current File` command (`Ctrl+Shift+S`)
- `API Key Watchdog: Open Dashboard` command
- Right-click context menu integration
