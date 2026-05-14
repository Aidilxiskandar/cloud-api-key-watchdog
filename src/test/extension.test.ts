import * as assert from 'assert';
import * as vscode from 'vscode';


// Import functions from your extension for testing
// Note: You may need to export these functions from extension.ts first
import {
	detectSecrets,
	detectWithRegex,
	detectWithEntropy,
	calculateShannonEntropy,
	extractStringLiterals,
	isCommonString,
	shouldSkipFile,

} from '../extension';

suite('Cloud API Key Watchdog Test Suite', () => {
	// Setup before all tests
	suiteSetup(async () => {
		console.log('Starting API Key Watchdog tests...');
		// Ensure extension is activated
		const ext = vscode.extensions.getExtension('your-publisher-name.cloud-api-key-watchdog');
		if (ext) {
			await ext.activate();
		}
	});

	// Teardown after all tests
	suiteTeardown(() => {
		console.log('All tests completed');
	});

	// Setup before each test
	setup(() => {
		console.log('Running test...');
	});

	// Teardown after each test
	teardown(() => {
		console.log('Test completed');
	});

	// ==================== REGEX DETECTION TESTS ====================
	suite('Regex Detection Tests', () => {
		test('Should detect AWS Access Key (AKIA format)', () => {
			const content = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('AWS Access Key'));
		});

		test('Should detect AWS Access Key (ASIA format)', () => {
			const content = 'aws_access_key_id = "ASIAIOSFODNN7EXAMPLE"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('AWS Access Key'));
		});

		test('Should detect AWS Secret Key', () => {
			const content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('AWS Secret Key'));
		});

		test('Should detect Google API Key', () => {
			const content = 'const googleApiKey = "AIzaSyDdI0hCZtE6vyBmI-kx5Cq7s3Y0EXAMPLE"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('Google API Key'));
		});

		test('Should detect GitHub Token', () => {
			const content = 'github_token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('GitHub Token'));
		});

		test('Should detect Slack Token', () => {
			const content = 'slack_token = "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('Slack Token'));
		});

		test('Should detect Stripe Key', () => {
			const content = 'stripe_key = "sk_live_12345678901234567890123456789012"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('Stripe Key'));
		});

		test('Should detect Private Key', () => {
			const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			assert.ok(result.method.includes('Private Key'));
		});

		test('Should NOT flag false positives (example keys)', () => {
			const content = 'const apiKey = "YOUR_API_KEY_HERE";';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, false);
		});

		test('Should NOT flag false positives (test keys)', () => {
			const content = 'aws_key = "TEST_AWS_KEY_12345"';
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, false);
		});

		test('Should detect multiple keys in same file', () => {
			const content = `
                aws_key = "AKIAIOSFODNN7EXAMPLE"
                github_token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"
                google_key = "AIzaSyDdI0hCZtE6vyBmI-kx5Cq7s3Y0EXAMPLE"
            `;
			const result = detectWithRegex(content);
			assert.strictEqual(result.found, true);
			// Should detect at least one of them
		});
	});

	// ==================== ENTROPY DETECTION TESTS ====================
	suite('Entropy Detection Tests', () => {
		test('Calculate entropy for random string (should be high)', () => {
			const randomString = 'aB3#kL9$xR2@mN5&vF7*';
			const entropy = calculateShannonEntropy(randomString);
			console.log(`Entropy for random string: ${entropy}`);
			assert.ok(entropy > 4.0, `Entropy ${entropy} should be > 4.0`);
		});

		test('Calculate entropy for repetitive string (should be low)', () => {
			const repetitiveString = 'aaaaaaaaaaaaaaaaaaaa';
			const entropy = calculateShannonEntropy(repetitiveString);
			console.log(`Entropy for repetitive string: ${entropy}`);
			assert.ok(entropy < 2.0, `Entropy ${entropy} should be < 2.0`);
		});

		test('Calculate entropy for English text (should be medium)', () => {
			const englishText = 'The quick brown fox jumps over the lazy dog';
			const entropy = calculateShannonEntropy(englishText);
			console.log(`Entropy for English text: ${entropy}`);
			assert.ok(entropy > 3.5 && entropy < 4.5, `Entropy ${entropy} should be between 3.5 and 4.5`);
		});

		test('Entropy should detect high-entropy strings above threshold', () => {
			const config = vscode.workspace.getConfiguration('apiKeyWatchdog');
			const threshold = config.get<number>('entropyThreshold', 4.5);

			const highEntropyString = 'xK9#mP2$rT5&vB8@nQ1*wE4%';
			const entropy = calculateShannonEntropy(highEntropyString);

			const result = detectWithEntropy(`"${highEntropyString}"`, threshold);
			console.log(`High entropy string: ${entropy} > ${threshold}? ${entropy > threshold}`);

			assert.ok(entropy > threshold);
			assert.strictEqual(result.threatDetected, true);
		});

		test('Entropy should NOT detect low-entropy strings', () => {
			const config = vscode.workspace.getConfiguration('apiKeyWatchdog');
			const threshold = config.get<number>('entropyThreshold', 4.5);

			const lowEntropyString = 'localhost';
			const entropy = calculateShannonEntropy(lowEntropyString);

			const result = detectWithEntropy(`"${lowEntropyString}"`, threshold);

			assert.ok(entropy < threshold);
			assert.strictEqual(result.threatDetected, false);
		});
	});

	// ==================== STRING EXTRACTION TESTS ====================
	suite('String Extraction Tests', () => {
		test('Should extract single-quoted strings', () => {
			const content = "const key = 'AKIAIOSFODNN7EXAMPLE';";
			const strings = extractStringLiterals(content);
			assert.ok(strings.includes('AKIAIOSFODNN7EXAMPLE'));
		});

		test('Should extract double-quoted strings', () => {
			const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
			const strings = extractStringLiterals(content);
			assert.ok(strings.includes('AKIAIOSFODNN7EXAMPLE'));
		});

		test('Should extract template literals', () => {
			const content = 'const key = `AKIAIOSFODNN7EXAMPLE`;';
			const strings = extractStringLiterals(content);
			assert.ok(strings.includes('AKIAIOSFODNN7EXAMPLE'));
		});

		test('Should extract multiple strings', () => {
			const content = `
                const aws = 'AKIAIOSFODNN7EXAMPLE';
                const github = "ghp_abcdefghijklmnopqrstuvwxyz";
                const slack = \`xoxb-123456789012-123456789012\`;
            `;
			const strings = extractStringLiterals(content);
			assert.strictEqual(strings.length, 3);
		});

		test('Should handle escaped quotes', () => {
			const content = "const str = 'It\\'s a string with escaped quote';";
			const strings = extractStringLiterals(content);
			assert.ok(strings[0].includes("It's"));
		});
	});

	// ==================== COMMON STRING FILTER TESTS ====================
	suite('Common String Filter Tests', () => {
		test('Should identify common strings like "localhost"', () => {
			assert.strictEqual(isCommonString('localhost'), true);
		});

		test('Should identify common strings like "password"', () => {
			assert.strictEqual(isCommonString('password'), true);
		});

		test('Should identify numeric strings', () => {
			assert.strictEqual(isCommonString('12345678'), true);
		});

		test('Should identify alphabetic strings', () => {
			assert.strictEqual(isCommonString('abcdefgh'), true);
		});

		test('Should NOT identify mixed alphanumeric with special chars as common', () => {
			assert.strictEqual(isCommonString('aB3#kL9$xR2@'), false);
		});
	});

	// ==================== FILE SKIP TESTS ====================
	suite('File Skip Tests', () => {
		test('Should skip node_modules files', () => {
			assert.strictEqual(shouldSkipFile('node_modules/package/index.js'), true);
		});

		test('Should skip .git files', () => {
			assert.strictEqual(shouldSkipFile('.git/config'), true);
		});

		test('Should skip binary files', () => {
			assert.strictEqual(shouldSkipFile('image.jpg'), true);
			assert.strictEqual(shouldSkipFile('document.pdf'), true);
			assert.strictEqual(shouldSkipFile('program.exe'), true);
		});

		test('Should NOT skip source code files', () => {
			assert.strictEqual(shouldSkipFile('src/app.js'), false);
			assert.strictEqual(shouldSkipFile('index.ts'), false);
			assert.strictEqual(shouldSkipFile('config.json'), false);
		});
	});

	// ==================== INTEGRATION TESTS ====================
	suite('Integration Tests', () => {
		test('detectSecrets should find AWS key in content', async () => {
			const content = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";';
			const result = await detectSecrets(content);
			assert.strictEqual(result.threatDetected, true);
			assert.ok(result.detectionMethod.includes('Regex'));
		});

		test('detectSecrets should find high-entropy string', async () => {
			const content = 'const secret = "xK9#mP2$rT5&vB8@nQ1*wE4%";';
			const result = await detectSecrets(content);
			assert.strictEqual(result.threatDetected, true);
			assert.ok(result.detectionMethod.includes('Entropy'));
		});

		test('detectSecrets should NOT flag safe content', async () => {
			const content = 'console.log("Hello, world!");';
			const result = await detectSecrets(content);
			assert.strictEqual(result.threatDetected, false);
		});

		test('detectSecrets should handle empty content', async () => {
			const result = await detectSecrets('');
			assert.strictEqual(result.threatDetected, false);
		});

		test('detectSecrets should handle large files', async () => {
			// Generate large content
			let content = '';
			for (let i = 0; i < 1000; i++) {
				content += `console.log("Line ${i}");\n`;
			}
			// Add a secret somewhere in the middle
			content += 'const awsKey = "AKIAIOSFODNN7EXAMPLE";\n';

			const result = await detectSecrets(content);
			assert.strictEqual(result.threatDetected, true);
		});
	});

	// ==================== VS CODE COMMAND TESTS ====================
	suite('VS Code Command Tests', () => {
		test('Extension commands should be registered', async () => {
			const commands = await vscode.commands.getCommands();

			assert.ok(commands.includes('apiKeyWatchdog.scanCurrentFile'),
				'Scan command should be registered');
		});

		test('Extension configuration should exist', () => {
			const config = vscode.workspace.getConfiguration('apiKeyWatchdog');

			assert.ok(config.has('enableEntropyDetection'));
			assert.ok(config.has('entropyThreshold'));
			assert.ok(config.has('dashboardUrl'));
		});

		test('Default configuration values should be set', () => {
			const config = vscode.workspace.getConfiguration('apiKeyWatchdog');

			assert.strictEqual(config.get<boolean>('enableEntropyDetection'), true);
			assert.strictEqual(config.get<number>('entropyThreshold'), 4.5);
			assert.strictEqual(config.get<string>('dashboardUrl'), 'http://127.0.0.1:5000');
		});
	});

	// ==================== PERFORMANCE TESTS ====================
	suite('Performance Tests', () => {
		test('Regex detection should be fast for large files', () => {
			// Generate a 1MB file
			let content = '';
			for (let i = 0; i < 10000; i++) {
				content += `Line ${i}: Some content here\n`;
			}

			const startTime = Date.now();
			detectWithRegex(content);
			const endTime = Date.now();
			const duration = endTime - startTime;

			console.log(`Regex detection on 1MB file took ${duration}ms`);
			assert.ok(duration < 500, `Detection took ${duration}ms, should be <500ms`);
		});

		test('Entropy calculation should be fast for large strings', () => {
			const largeString = 'aB3#kL9$xR2@mN5&vF7*'.repeat(1000);

			const startTime = Date.now();
			calculateShannonEntropy(largeString);
			const endTime = Date.now();
			const duration = endTime - startTime;

			console.log(`Entropy calculation on ${largeString.length} chars took ${duration}ms`);
			assert.ok(duration < 100, `Calculation took ${duration}ms, should be <100ms`);
		});
	});
})