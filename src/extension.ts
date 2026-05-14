import * as vscode from 'vscode';
import axios from 'axios';

// Shared output channel — visible in the OUTPUT panel (next to TERMINAL).
// Assigned in activate() which always runs before any logToDashboard call.
let outputChannel!: vscode.OutputChannel;

// ==================== Interfaces ====================
interface Finding {
    line: number;
    column: number;
    matchedText: string;
    detectionMethod: string;
    entropyScore?: number;
}

interface DetectionResult {
    threatDetected: boolean;
    findings: Finding[];
    detectionMethod: string;
    matchedKey?: string;
    entropyScore: number;
}

interface LogPayload {
    filename: string;
    detected_key: string;
    detection_method: string;
    entropy_score: number;
    timestamp: string;
    status: string;
    machine_id: string;
    findings?: Finding[];
}

// ==================== Detection Patterns ====================
const SECRET_PATTERNS = [
    { name: 'AWS Access Key', pattern: /(?:AKIA|ASIA|ABIA)[A-Z0-9]{16}/g },
    { name: 'AWS Secret Key', pattern: /aws(?:_)?secret(?:_)?access(?:_)?key[\s]*[:=][\s]*[A-Za-z0-9\/\+]{40}/gi },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/g },
    { name: 'Google OAuth Client ID', pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g },
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,251}/g },
    { name: 'Generic API Key', pattern: /(api[_-]?key|secret|token|password)[\s]*[:=][\s]*['"]?[A-Za-z0-9_\-\.]{16,}['"]?/gi },
    { name: 'Private Key', pattern: /-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}/g },
    { name: 'Stripe Key', pattern: /(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}/g }
];

const COMMON_STRINGS = [
    'true', 'false', 'null', 'undefined',
    'localhost', 'password', 'username',
    'SELECT', 'INSERT', 'UPDATE', 'DELETE',
    'http://', 'https://', 'function', 'return',
    'console.log', 'error', 'warning', 'info'
];

// ==================== Helper: Find line/column ====================
function getLineAndColumn(content: string, index: number): { line: number; column: number } {
    const lines = content.substring(0, index).split('\n');
    const line = lines.length;
    const column = lines.length === 0 ? 1 : lines[lines.length - 1].length + 1;
    return { line, column };
}

// ==================== Regex Detection ====================
function detectWithRegexDetailed(content: string): Finding[] {
    const findings: Finding[] = [];
    for (const pattern of SECRET_PATTERNS) {
        pattern.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = pattern.pattern.exec(content)) !== null) {
            const matchedText = match[0];
            if (isFalsePositive(matchedText)) continue;
            const { line, column } = getLineAndColumn(content, match.index);
            findings.push({
                line,
                column,
                matchedText,
                detectionMethod: `Regex (${pattern.name})`,
                entropyScore: undefined
            });
        }
    }
    return findings;
}

// ==================== Entropy Detection ====================
function detectWithEntropyDetailed(content: string, threshold: number): Finding[] {
    const findings: Finding[] = [];
    const stringLiterals = extractStringLiteralsWithPositions(content);
    for (const lit of stringLiterals) {
        if (lit.text.length < 8 || isCommonString(lit.text)) continue;
        const entropy = calculateShannonEntropy(lit.text);
        if (entropy > threshold) {
            findings.push({
                line: lit.line,
                column: lit.column,
                matchedText: lit.text,
                detectionMethod: 'High Entropy Detection',
                entropyScore: entropy
            });
        }
    }
    return findings;
}

function extractStringLiteralsWithPositions(content: string): { text: string; line: number; column: number }[] {
    const result: { text: string; line: number; column: number }[] = [];
    const regex = /(['"`])(?:(?=(\\?))\2.)*?\1/g;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
        let clean = match[0].slice(1, -1);
        clean = clean.replace(/\\['"`]/g, (m) => m[1]);
        const { line, column } = getLineAndColumn(content, match.index);
        result.push({ text: clean, line, column });
    }
    return result;
}

// ==================== Main Orchestrator ====================
async function detectSecretsDetailed(content: string): Promise<DetectionResult> {
    const config = vscode.workspace.getConfiguration('apiKeyWatchdog');
    const enableEntropy = config.get<boolean>('enableEntropyDetection', true);
    const entropyThreshold = config.get<number>('entropyThreshold', 4.5);

    let allFindings: Finding[] = [];
    allFindings.push(...detectWithRegexDetailed(content));
    if (enableEntropy) {
        allFindings.push(...detectWithEntropyDetailed(content, entropyThreshold));
    }

    const uniqueFindings = allFindings.filter((f, idx, self) => {
        // 1. Drop exact duplicates (same line, column and text)
        if (idx !== self.findIndex(g =>
            g.line === f.line && g.column === f.column && g.matchedText === f.matchedText
        )) { return false; }

        // 2. Drop a Generic API Key finding when a more specific pattern on the
        //    same line already captured the actual key value that is contained
        //    inside this Generic match (e.g. `apiKey = "AIza..."` vs `AIza...`).
        if (f.detectionMethod.includes('Generic API Key')) {
            const coveredBySpecific = self.some((g, gIdx) =>
                gIdx !== idx &&
                g.line === f.line &&
                !g.detectionMethod.includes('Generic API Key') &&
                f.matchedText.includes(g.matchedText)
            );
            if (coveredBySpecific) { return false; }
        }

        return true;
    });

    if (uniqueFindings.length > 0) {
        const firstFinding = uniqueFindings[0];
        return {
            threatDetected: true,
            findings: uniqueFindings,
            detectionMethod: uniqueFindings.length > 1 ? `Multiple (${uniqueFindings.length} threats)` : firstFinding.detectionMethod,
            matchedKey: firstFinding.matchedText,
            entropyScore: firstFinding.entropyScore || 0
        };
    }

    return {
        threatDetected: false,
        findings: [],
        detectionMethod: 'None',
        entropyScore: 0
    };
}

// ==================== Legacy exports for tests ====================
async function detectSecrets(content: string): Promise<DetectionResult> {
    return detectSecretsDetailed(content);
}

function detectWithRegex(content: string): { found: boolean; method: string; matchedKey: string } {
    const findings = detectWithRegexDetailed(content);
    if (findings.length === 0) return { found: false, method: '', matchedKey: '' };
    return { found: true, method: findings[0].detectionMethod, matchedKey: findings[0].matchedText };
}

function detectWithEntropy(content: string, threshold: number): { threatDetected: boolean; method: string; matchedKey: string; score: number } {
    const findings = detectWithEntropyDetailed(content, threshold);
    if (findings.length === 0) return { threatDetected: false, method: '', matchedKey: '', score: 0 };
    return { threatDetected: true, method: 'High Entropy Detection', matchedKey: findings[0].matchedText, score: findings[0].entropyScore || 0 };
}

function extractStringLiterals(content: string): string[] {
    return extractStringLiteralsWithPositions(content).map(l => l.text);
}

// ==================== Helper functions ====================
function isFalsePositive(matchedKey: string): boolean {
    const falsePositives = [
        /^EXAMPLE_/i, /^SAMPLE_/i, /^TEST_/i, /^MOCK_/i, /^FAKE_/i,
        /your-api-key/i, /<YOUR_/i
    ];
    return falsePositives.some(pattern => pattern.test(matchedKey));
}

function isCommonString(str: string): boolean {
    const lowerStr = str.toLowerCase();

    // Known common/safe keyword substrings
    if (COMMON_STRINGS.some(common => lowerStr.includes(common))) { return true; }

    // Real secrets never contain spaces — format strings, sentences, and
    // code templates (f-strings, template literals) almost always do
    if (/\s/.test(str)) { return true; }

    // Python / JS template placeholders: {variable}, {obj.attr}, {val:^70}
    if (/\{[A-Za-z_][^}]*\}/.test(str)) { return true; }

    // strftime / date format codes: %Y, %m, %d, %H, %M, %S …
    if (/%[YymdHMSfBbAaIpjZz]/.test(str)) { return true; }

    // ANSI / terminal colour names embedded in strings
    if (/\b(BOLD|CYAN|RED|GREEN|BLUE|YELLOW|RESET|END|UNDERLINE|Colors)\b/i.test(str)) { return true; }

    // Pure character-class strings (no real entropy for secrets)
    const simplePatterns = [/^[0-9]+$/, /^[A-Za-z]+$/, /^[0-9]+[A-Za-z]+$/, /^[A-Za-z]+[0-9]+$/];
    if (simplePatterns.some(p => p.test(str))) { return true; }

    // Looks like a file path or URL fragment
    if (/^(\.{0,2}\/|[A-Za-z]:\\)/.test(str)) { return true; }

    // Mostly punctuation / brackets — code structure, not a secret
    const punctuationRatio = (str.match(/[^A-Za-z0-9]/g) || []).length / str.length;
    if (punctuationRatio > 0.4) { return true; }

    return false;
}

function calculateShannonEntropy(str: string): number {
    const charCount: { [key: string]: number } = {};
    const len = str.length;
    for (let i = 0; i < len; i++) {
        const char = str[i];
        charCount[char] = (charCount[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in charCount) {
        const probability = charCount[char] / len;
        entropy -= probability * Math.log2(probability);
    }
    return parseFloat(entropy.toFixed(2));
}

function shouldSkipFile(filePath: string): boolean {
    const skipPatterns = [
        /node_modules/, /\.git/, /\.vscode/, /\.vsix/, /\.exe$/, /\.dll$/,
        /\.jpg$/, /\.png$/, /\.gif$/, /\.pdf$/, /\.zip$/, /\.lock$/
    ];
    return skipPatterns.some(pattern => pattern.test(filePath));
}

// ==================== Dashboard logging ====================
async function logToDashboard(payload: LogPayload): Promise<void> {
    const config = vscode.workspace.getConfiguration('apiKeyWatchdog');
    const dashboardUrl = config.get<string>('dashboardUrl', 'http://127.0.0.1:5000');
    const apiKey = config.get<string>('dashboardApiKey', '');
    const serverUrl = `${dashboardUrl}/api/log`;

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) { headers['X-API-Key'] = apiKey; }

    try {
        await axios.post(serverUrl, payload, { headers, timeout: 3000 });
        outputChannel.appendLine(`[${payload.timestamp}] ✅ Logged to dashboard — ${payload.filename} (${payload.status})`);
    } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        outputChannel.appendLine(`[${payload.timestamp}] ❌ Dashboard unreachable: ${msg}`);
        outputChannel.appendLine(`   Make sure Flask is running: cd dashboard-server && python app.py`);
        vscode.window.showWarningMessage(
            `API Watchdog: Could not reach dashboard (${msg})`,
            'Open Dashboard Anyway'
        ).then(action => {
            if (action === 'Open Dashboard Anyway') {
                vscode.env.openExternal(vscode.Uri.parse(dashboardUrl));
            }
        });
    }
}

// ==================== VS Code Activation ====================
export function activate(context: vscode.ExtensionContext) {
    const config = vscode.workspace.getConfiguration('apiKeyWatchdog');
    const dashboardUrl = config.get<string>('dashboardUrl', 'http://127.0.0.1:5000');
    const machineId = vscode.env.machineId;
    const dashboardWithId = `${dashboardUrl}?machine_id=${machineId}`;

    // --- Output channel (appears in OUTPUT panel, URLs are Ctrl+Click-able) ---
    outputChannel = vscode.window.createOutputChannel('API Key Watchdog');
    outputChannel.appendLine('🔒 API Key Watchdog — Active');
    outputChannel.appendLine('─────────────────────────────────────────────');
    outputChannel.appendLine('Dashboard (Ctrl+Click to open):');
    outputChannel.appendLine(dashboardWithId);
    outputChannel.appendLine('─────────────────────────────────────────────');
    outputChannel.appendLine('');
    outputChannel.show(true);

    // --- Status bar button (always visible at the bottom) ---
    const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.text = '$(shield) Dashboard';
    statusBarItem.tooltip = `Open API Key Watchdog dashboard\n${dashboardWithId}`;
    statusBarItem.command = 'apiKeyWatchdog.openDashboard';
    statusBarItem.show();

    // --- Commands ---
    const openDashboardDisposable = vscode.commands.registerCommand('apiKeyWatchdog.openDashboard', () => {
        const url = vscode.workspace.getConfiguration('apiKeyWatchdog').get<string>('dashboardUrl', 'http://127.0.0.1:5000');
        const fullUrl = `${url}?machine_id=${vscode.env.machineId}`;
        vscode.env.openExternal(vscode.Uri.parse(fullUrl));
    });

    const saveDisposable = vscode.workspace.onWillSaveTextDocument((event) => {
        event.waitUntil(handleFileSave(event));
    });

    const scanDisposable = vscode.commands.registerCommand('apiKeyWatchdog.scanCurrentFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) { return; }
        const fileContent = editor.document.getText();
        const filePath = vscode.workspace.asRelativePath(editor.document.uri);
        const result = await detectSecretsDetailed(fileContent);
        if (result.threatDetected) {
            const items = result.findings.map(f => ({
                label: `$(warning)  Line ${f.line}, Col ${f.column}`,
                description: f.detectionMethod,
                detail: `"${f.matchedText.substring(0, 100)}${f.matchedText.length > 100 ? '…' : ''}"`
            }));
            vscode.window.showQuickPick(items, {
                title: `🔒 ${result.findings.length} secret(s) in ${filePath}`,
                placeHolder: 'Read-only scan results'
            });
        } else {
            vscode.window.showInformationMessage('✅ No secrets detected in this file.');
        }
    });

    context.subscriptions.push(saveDisposable, scanDisposable, openDashboardDisposable, statusBarItem, outputChannel);
}

// Returns TextEdit[] consumed by event.waitUntil — the only reliable way to
// control what VS Code actually writes to disk.  An empty array = save as-is.
async function handleFileSave(event: vscode.TextDocumentWillSaveEvent): Promise<vscode.TextEdit[]> {
    const document = event.document;
    const fileContent = document.getText();
    const filePath = vscode.workspace.asRelativePath(document.uri);

    if (shouldSkipFile(filePath)) { return []; }

    const detectionResult = await detectSecretsDetailed(fileContent);
    if (!detectionResult.threatDetected) { return []; }

    const total = detectionResult.findings.length;
    const fileName = filePath.split(/[\\/]/).pop() ?? filePath;

    // Build QuickPick items once — reused if user picks "Show Details"
    const detailItems = detectionResult.findings.map(f => ({
        label: `$(warning)  Line ${f.line}, Col ${f.column}`,
        description: f.detectionMethod,
        detail: `"${f.matchedText.substring(0, 100)}${f.matchedText.length > 100 ? '…' : ''}"`
    }));

    // Show modal dialog and loop if user wants to view details first
    let choice: string | undefined;
    do {
        choice = await vscode.window.showWarningMessage(
            `🚨 ${total} exposed secret(s) detected in ${fileName}`,
            {
                modal: true,
                detail: `File: ${filePath}\n\nBlocking the save keeps your credentials safe.\nChoose "Save Anyway" only if you are certain these are not real keys.`
            },
            'Block Save',
            'Save Anyway',
            'Show Details'
        );

        if (choice === 'Show Details') {
            await vscode.window.showQuickPick(detailItems, {
                title: `🔒 Secrets in ${fileName} — ${total} finding(s)`,
                placeHolder: 'Showing all detected secrets (read-only) — close to return'
            });
            // Loop back: re-show the action dialog after details are closed
        }
    } while (choice === 'Show Details');

    // undefined = user dismissed the dialog (Escape / ✕) → treat as Block Save
    const userAllowedSave = choice === 'Save Anyway';
    const status = userAllowedSave ? 'BYPASSED' : 'BLOCKED';
    outputChannel.appendLine(`[Detection] ${status} — ${total} secret(s) in ${filePath}`);

    const now = new Date();
    const pad = (n: number) => String(n).padStart(2, '0');
    const localTimestamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

    await logToDashboard({
        filename: filePath,
        detected_key: detectionResult.matchedKey || 'Multiple',
        detection_method: detectionResult.detectionMethod,
        entropy_score: detectionResult.entropyScore,
        timestamp: localTimestamp,
        status,
        machine_id: vscode.env.machineId,
        findings: detectionResult.findings
    });

    if (!userAllowedSave) {
        const fullRange = new vscode.Range(
            document.positionAt(0),
            document.positionAt(fileContent.length)
        );

        let diskText: string;
        try {
            const diskBytes = await vscode.workspace.fs.readFile(document.uri);
            diskText = Buffer.from(diskBytes).toString('utf8');
        } catch {
            // New file with no prior disk version — cannot silently block
            vscode.window.showWarningMessage(
                '⚠️ API Watchdog: cannot block save for a new file. Remove the secret before saving.'
            );
            return [];
        }

        // After VS Code finishes writing the clean disk content, immediately
        // re-apply the user's original edits so the file is dirty again with
        // their work intact — no extra steps needed on their end.
        const userContent = fileContent;
        const onceListener = vscode.workspace.onDidSaveTextDocument(savedDoc => {
            if (savedDoc.uri.toString() !== document.uri.toString()) { return; }
            onceListener.dispose();
            const edit = new vscode.WorkspaceEdit();
            const restoreRange = new vscode.Range(
                savedDoc.positionAt(0),
                savedDoc.positionAt(savedDoc.getText().length)
            );
            edit.replace(savedDoc.uri, restoreRange, userContent);
            vscode.workspace.applyEdit(edit);
        });

        // Returning this TextEdit makes VS Code write diskText to disk (no change),
        // while the listener above restores the user's content right after.
        return [vscode.TextEdit.replace(fullRange, diskText)];
    }

    return []; // Save Anyway — let VS Code write the file as-is
}

export function deactivate() { }

// Exports for tests
export { detectSecrets, detectWithRegex, detectWithEntropy, calculateShannonEntropy, extractStringLiterals, isCommonString, shouldSkipFile, Finding, DetectionResult, LogPayload };