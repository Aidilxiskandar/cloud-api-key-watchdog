"""
Cloud API Key Detection Dashboard
Receives logs from VS Code extension and displays them in a web dashboard.
"""

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from datetime import datetime
import json
import os
import re
import math
import io
import zipfile
import requests as http_req
from concurrent.futures import ThreadPoolExecutor, as_completed
from werkzeug.utils import secure_filename
import pandas as pd
import plotly
import plotly.express as px
import plotly.utils

# ─── Secret detection patterns (mirrors extension.ts) ───────────────────────
_SECRET_PATTERNS = [
    ('AWS Access Key',      re.compile(r'(?:AKIA|ASIA|ABIA)[A-Z0-9]{16}')),
    ('AWS Secret Key',      re.compile(r'aws(?:_)?secret(?:_)?access(?:_)?key\s*[:=]\s*[A-Za-z0-9\/\+]{40}', re.I)),
    ('Google API Key',      re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ('Google OAuth Client', re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com')),
    ('GitHub Token',        re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,251}')),
    ('Generic API Key',     re.compile(r'(?:api[_\-]?key|secret|token|password)\s*[:=]\s*[\'"]?[A-Za-z0-9_\-\.]{16,}[\'"]?', re.I)),
    ('Private Key',         re.compile(r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----')),
    ('Slack Token',         re.compile(r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}')),
    ('Stripe Key',          re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}')),
]

_FALSE_POSITIVES = [
    re.compile(r'^EXAMPLE_', re.I), re.compile(r'^SAMPLE_', re.I),
    re.compile(r'^TEST_',    re.I), re.compile(r'^MOCK_',   re.I),
    re.compile(r'^FAKE_',    re.I), re.compile(r'your.api.key', re.I),
    re.compile(r'<YOUR_'),         re.compile(r'placeholder', re.I),
    re.compile(r'^\*+$'),          re.compile(r'^x+$', re.I),
]

# Strings that look high-entropy but are not secrets
_COMMON_ENTROPY_SKIP = re.compile(
    r'(localhost|example\.com|placeholder|undefined|null|true|false'
    r'|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    r'|0123456789|sha\d|md5|base64|charset|utf-8|content-type)',
    re.I
)

_TEXT_EXTENSIONS = {
    '.py','.js','.ts','.jsx','.tsx','.json','.yaml','.yml','.env',
    '.txt','.md','.sh','.bash','.rb','.go','.java','.php','.cs',
    '.cpp','.c','.h','.rs','.swift','.kt','.xml','.toml','.ini',
    '.cfg','.conf','.properties','.gradle','.tf','.hcl','.vue',
    '.svelte','.html','.css','.scss','.less','.sql','.r','.ipynb',
    '.dockerfile', '.Makefile', '.rake',
}

def _should_scan(path):
    name = os.path.basename(path).lower()
    if name in {'.env', 'credentials', 'secrets', '.netrc', '.npmrc',
                '.pypirc', 'config', '.aws', 'terraform.tfvars'}:
        return True
    _, ext = os.path.splitext(name)
    return ext in _TEXT_EXTENSIONS

def _entropy(s):
    if not s: return 0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    return round(-sum((v/len(s))*math.log2(v/len(s)) for v in freq.values()), 2)

# Matches quoted string literals: "...", '...', `...`
_STRING_LITERAL = re.compile(r'[\'"`]([^\'"` \t\r\n]{8,120})[\'"`]')
_ENTROPY_THRESHOLD = 4.5

def _scan_text(content, filename):
    findings, seen = [], set()
    lines = content.splitlines()

    for ln, line in enumerate(lines, 1):
        # ── Regex pattern matching ──
        for name, pat in _SECRET_PATTERNS:
            for m in pat.finditer(line):
                text = m.group()
                if any(fp.search(text) for fp in _FALSE_POSITIVES):
                    continue
                key = (ln, name, text)
                if key in seen: continue
                seen.add(key)
                findings.append({
                    'file': filename, 'line': ln, 'column': m.start() + 1,
                    'method': name, 'matched_text': text[:120],
                    'entropy': _entropy(text),
                })

        # ── Entropy-based detection on string literals ──
        for m in _STRING_LITERAL.finditer(line):
            text = m.group(1)
            # Skip if it looks like a common non-secret string
            if _COMMON_ENTROPY_SKIP.search(text):
                continue
            # Skip pure alpha or pure digit strings — low information density
            if text.isalpha() or text.isdigit():
                continue
            ent = _entropy(text)
            if ent >= _ENTROPY_THRESHOLD:
                key = (ln, 'High Entropy', text)
                if key in seen: continue
                seen.add(key)
                findings.append({
                    'file': filename, 'line': ln, 'column': m.start() + 1,
                    'method': 'High Entropy', 'matched_text': text[:120],
                    'entropy': ent,
                })

    return findings

app = Flask(__name__)
CORS(app)

DATA_FILE = os.path.join(os.path.dirname(__file__), "detections.json")

def load_detections(machine_id=None):
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            data = json.load(f)
        if machine_id:
            data = [d for d in data if d.get('machine_id') == machine_id]
        return data
    return []

def save_detection(detection):
    all_detections = load_detections()
    all_detections.append(detection)
    with open(DATA_FILE, 'w') as f:
        json.dump(all_detections, f, indent=2)

# ------------------- API Endpoint for VS Code Extension -------------------
@app.route('/api/log', methods=['POST'])
def log_detection():
    """
    Receive detection log from VS Code extension.
    Expected JSON payload:
    {
        "filename": "config/database.py",
        "detected_key": "AKIAIOSFODNN7EXAMPLE",
        "detection_method": "Regex (AWS)",
        "entropy_score": 0.0,
        "timestamp": "2024-05-20 14:30:05",
        "status": "BLOCKED"
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No JSON payload"}), 400

        # Log to console (for debugging)
        print(f"\n🔒 SECURITY DETECTION RECEIVED:")
        print(f"   File: {data.get('filename')}")
        print(f"   Method: {data.get('detection_method')}")
        print(f"   Key: {data.get('detected_key')}")
        print(f"   Time: {data.get('timestamp')}")
        print(f"   Status: {data.get('status')}\n")

        # Save to file
        save_detection(data)

        return jsonify({"status": "success", "message": "Detection logged"}), 200

    except Exception as e:
        print(f"Error processing log: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    machine_id = request.args.get('machine_id')
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "detections_count": len(load_detections(machine_id))
    })

# ------------------- Dashboard UI Routes -------------------
@app.route('/')
def dashboard():
    """Render the main dashboard page."""
    return render_template('index.html')

@app.route('/api/detections')
def get_detections():
    machine_id = request.args.get('machine_id')
    return jsonify(load_detections(machine_id))

@app.route('/api/stats')
def get_stats():
    machine_id = request.args.get('machine_id')
    detections = load_detections(machine_id)
    if not detections:
        return jsonify({
            'total': 0,
            'by_method': {},
            'by_status': {},
            'daily_counts': {},
            'unique_files': 0
        })

    df = pd.DataFrame(detections)

    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Daily counts keyed as "YYYY-MM-DD" strings
    daily_counts = df.groupby(df['timestamp'].dt.date).size().to_dict()
    daily_counts_str_keys = {str(k): v for k, v in daily_counts.items()}

    # Aggregate detection methods from the findings array in each record.
    # The top-level detection_method is a summary string ("Multiple (40 threats)")
    # so we drill into findings for accurate per-pattern counts.
    method_counts = {}
    for det in detections:
        findings_list = det.get('findings') or []
        if findings_list:
            for f in findings_list:
                method = f.get('detectionMethod', 'Unknown')
                if 'Entropy' in method:
                    key = 'High Entropy'
                elif method.startswith('Regex (') and method.endswith(')'):
                    key = method[7:-1]   # "AWS Access Key" from "Regex (AWS Access Key)"
                else:
                    key = method
                method_counts[key] = method_counts.get(key, 0) + 1
        else:
            # Fallback for records saved before findings array was added
            key = det.get('detection_method', 'Unknown')
            method_counts[key] = method_counts.get(key, 0) + 1

    # Timestamps back to strings before to_dict so pandas Timestamps serialise cleanly
    recent_df = df.sort_values('timestamp', ascending=False).head(10).copy()
    recent_df['timestamp'] = recent_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')

    stats = {
        'total': len(df),
        'by_method': method_counts,
        'by_status': df['status'].value_counts().to_dict(),
        'daily_counts': daily_counts_str_keys,
        'unique_files': df['filename'].nunique(),
        'recent': recent_df.to_dict('records')
    }
    return jsonify(stats)

@app.route('/api/clear', methods=['POST'])
def clear_detections():
    """Clear all detections (for testing)."""
    with open(DATA_FILE, 'w') as f:
        json.dump([], f)
    return jsonify({"status": "cleared"})

# ─── Manual Scanner ─────────────────────────────────────────────────────────
@app.route('/scanner')
def scanner():
    return render_template('scanner.html')

def _fetch_and_scan(owner, repo, branch, path):
    """Fetch one raw file and return (path, findings). Used in thread pool."""
    url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}'
    try:
        r = http_req.get(url, timeout=6)
        if not r.ok:
            return path, []
        text = r.content.decode('utf-8', errors='replace')
        return path, _scan_text(text, path)
    except Exception:
        return path, []

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    url = (request.json or {}).get('url', '').strip()

    # Support URLs with trailing slash, subpaths, or .git suffix
    m = re.match(r'https?://github\.com/([^/\s]+)/([^/\s\.]+)', url)
    if not m:
        return jsonify({'error': 'Enter a valid public GitHub URL — https://github.com/owner/repo'}), 400
    owner, repo = m.group(1), m.group(2)
    gh = {'Accept': 'application/vnd.github.v3+json', 'User-Agent': 'api-key-watchdog'}

    # Default branch
    try:
        r = http_req.get(f'https://api.github.com/repos/{owner}/{repo}',
                         headers=gh, timeout=10)
    except Exception as e:
        return jsonify({'error': f'Network error reaching GitHub: {e}'}), 502

    if r.status_code == 403:
        limit = r.headers.get('X-RateLimit-Remaining', '?')
        return jsonify({'error': f'GitHub rate limit hit (remaining: {limit}). Wait an hour or add a token.'}), 429
    if r.status_code == 404:
        return jsonify({'error': 'Repository not found or is private.'}), 404
    if not r.ok:
        return jsonify({'error': f'GitHub API returned {r.status_code}: {r.text[:200]}'}), 502

    branch = r.json().get('default_branch', 'main')
    print(f'[scanner] {owner}/{repo} @ {branch}')

    # Full recursive file tree (one API call)
    try:
        r = http_req.get(
            f'https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1',
            headers=gh, timeout=20)
    except Exception as e:
        return jsonify({'error': f'Could not fetch file tree: {e}'}), 502

    if r.status_code == 403:
        return jsonify({'error': 'GitHub rate limit hit while fetching tree. Try again later.'}), 429
    if not r.ok:
        return jsonify({'error': f'Tree API returned {r.status_code}'}), 502

    tree_data = r.json()
    blobs = [
        i for i in tree_data.get('tree', [])
        if i['type'] == 'blob' and _should_scan(i['path'])
    ]
    # Cap at 200 files; prioritise likely-secret files (.env, config*, credentials*)
    def _priority(p):
        name = os.path.basename(p).lower()
        if any(k in name for k in ('.env', 'secret', 'credential', 'config', 'token', 'key')):
            return 0
        return 1
    blobs.sort(key=lambda i: _priority(i['path']))
    blobs = blobs[:200]

    print(f'[scanner] fetching {len(blobs)} files concurrently…')

    # Fetch all files concurrently (20 workers)
    findings, scanned = [], []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {
            pool.submit(_fetch_and_scan, owner, repo, branch, i['path']): i['path']
            for i in blobs
        }
        for future in as_completed(futures):
            path, file_findings = future.result()
            if file_findings is not None:
                scanned.append(path)
                findings.extend(file_findings)

    print(f'[scanner] done — {len(scanned)} scanned, {len(findings)} findings')

    return jsonify({
        'repo': f'{owner}/{repo}', 'branch': branch,
        'files_scanned': len(scanned), 'total_files': len(blobs),
        'findings': findings, 'truncated': len(blobs) >= 200,
    })

@app.route('/api/scan/upload', methods=['POST'])
def scan_upload():
    files = request.files.getlist('files')
    if not files:
        return jsonify({'error': 'No files received.'}), 400
    findings, scanned = [], []
    for f in files:
        name = secure_filename(f.filename or 'file')
        if name.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(f.read())) as zf:
                    for zname in zf.namelist():
                        if not _should_scan(zname): continue
                        try:
                            text = zf.read(zname).decode('utf-8', errors='replace')
                            scanned.append(zname)
                            findings.extend(_scan_text(text, zname))
                        except (UnicodeDecodeError, OSError) as scan_err:
                            print(f'[scanner] skipping {zname}: {scan_err}')
                            continue
            except Exception as e:
                return jsonify({'error': f'Bad zip file: {e}'}), 400
        else:
            if not _should_scan(name): continue
            text = f.read().decode('utf-8', errors='replace')
            scanned.append(name)
            findings.extend(_scan_text(text, name))
    return jsonify({'files_scanned': len(scanned), 'findings': findings})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = '0.0.0.0'
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    print(f"Dashboard running on http://{host}:{port}")
    app.run(debug=debug_mode, port=port, host=host)