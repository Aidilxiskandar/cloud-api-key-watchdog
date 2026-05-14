# Cloud API Key Watchdog 🔒

> Real-time secret detection that **blocks saves** when exposed API keys are found — keeping your credentials off disk and out of version control.

---

## Features

### 🛡 Save-Time Protection
Every time you save a file, the extension scans for exposed secrets. If a threat is found, a modal dialog gives you full control:

- **Block Save** — the file on disk stays clean; your edits are preserved in the editor so you can fix the secret and try again
- **Save Anyway** — allows the save and logs it as `BYPASSED` in the dashboard
- **Show Details** — opens a searchable list of every finding (line, column, detection type, matched text) before you decide

### 🔍 Two Detection Methods

**Regex Pattern Matching** — catches 9 known secret formats:
- AWS Access Key & Secret Key
- Google API Key & OAuth Client ID
- GitHub Tokens (`ghp_`, `gho_`, `ghs_`, `ghu_`, `ghr_`)
- Stripe Keys (`sk_live_`, `pk_live_`)
- Slack Tokens (`xoxb-`, `xoxp-`)
- RSA / DSA / EC / OpenSSH Private Keys
- Generic API Keys, secrets, tokens, and passwords

**Shannon Entropy Detection** — catches high-randomness strings (threshold: 4.5 bits) that don't match any known pattern, such as custom database passwords and encryption keys.

### 📊 Monitoring Dashboard
A local Flask web dashboard (requires Python — see Setup) at `http://127.0.0.1:5000` shows:
- Real-time detection stats and charts
- Full detection history with file, method, line numbers, and status
- Blocked vs Bypassed breakdown

### 🔎 Manual Repository Scanner
Available at `http://127.0.0.1:5000/scanner`:
- Scan any **public GitHub repository** by URL
- **Upload files or a ZIP archive** for offline scanning
- Severity ratings, filter bar, and CSV export

---

## Requirements

- **VS Code** 1.80.0 or later
- **Python 3.8+** and the Flask dashboard dependencies (for the dashboard and scanner features)

---

## Setup

### 1. Install the extension
Search for **Cloud API Key Watchdog** in the VS Code Extensions panel and click Install.

### 2. Start the dashboard (optional)
```bash
cd dashboard-server
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000` in your browser.

The extension works without the dashboard — it will still block saves and show detection details. The dashboard just adds logging and monitoring.

---

## Extension Settings

| Setting | Default | Description |
|---|---|---|
| `apiKeyWatchdog.enableEntropyDetection` | `true` | Enable Shannon entropy-based detection |
| `apiKeyWatchdog.entropyThreshold` | `4.5` | Entropy score above which a string is flagged |
| `apiKeyWatchdog.dashboardUrl` | `http://127.0.0.1:5000` | URL of your Flask dashboard server |

---

## Commands

| Command | Shortcut | Description |
|---|---|---|
| API Key Watchdog: Scan Current File | `Ctrl+Shift+S` | Manually scan the active file |
| API Key Watchdog: Open Dashboard | — | Open the monitoring dashboard in your browser |

Right-click in any editor to access **Scan Current File** from the context menu.

---

## How It Works

```
You press Ctrl+S
       │
       ▼
Extension intercepts the save (onWillSaveTextDocument)
       │
       ├─ Regex scan ──► matches known patterns (AWS, GitHub, Stripe…)
       │
       └─ Entropy scan ► flags high-entropy string literals (≥ 4.5 bits)
              │
              ▼
       Threat found?
       │
       ├─ NO  → save proceeds normally
       │
       └─ YES → modal dialog
                │
                ├─ Block Save   → disk unchanged, edits stay in editor
                ├─ Save Anyway  → saves + logs as BYPASSED
                └─ Show Details → QuickPick with every finding
```

---

## Known Limitations

- The dashboard and scanner require the Flask server to be running locally.
- Only **public** GitHub repositories can be scanned via URL in the scanner.
- Files larger than ~5 MB may take slightly longer to scan.

---

## Privacy

All detection data stays on your machine. Nothing is sent to any external server. The dashboard logs to a local `detections.json` file only.
