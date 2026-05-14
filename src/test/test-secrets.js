// ============================================================
//  API KEY WATCHDOG — Test File
//  Purpose : Trigger every detection type to verify the
//            extension, dashboard, and scanner all work.
//  Usage   : Open this file in VS Code and press Ctrl+S
//            The extension should intercept the save.
// ============================================================


// ── 1. AWS Access Key (Regex) ────────────────────────────────
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
const awsAccessKey2 = "ASIAIOSFODNN7EXAMPLE";


// ── 2. AWS Secret Key (Regex) ────────────────────────────────
const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";


// ── 3. Google API Key (Regex) ────────────────────────────────
const googleApiKey = "AIzaSyDdI0hCZtE6vyBmI-kx5Cq7s3Y0EXAMPLE";


// ── 4. GitHub Token (Regex) ──────────────────────────────────
const githubToken = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH";
const githubToken2 = "gho_abcdefghijklmnopqrstuvwxyzABCDEFGH";


// ── 5. Stripe Key (Regex) ────────────────────────────────────
const stripeSecret = "sk_live_12345678901234567890123456789012";
const stripePublic = "pk_live_12345678901234567890123456789012";


// ── 6. Slack Token (Regex) ───────────────────────────────────
const slackToken = "xoxb-123456789012-123456789012-abcdefghijklmnopqrs";


// ── 7. Private Key Header (Regex) ────────────────────────────
const privateKeyBlock = "-----BEGIN RSA PRIVATE KEY-----";


// ── 8. Generic API Key / Password (Regex) ────────────────────
const apiKey = "my_api_key_value_abcdefghijklmnop";
const token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc";
const password = "super_secret_password_XyZ12345678";


// ── 9. High Entropy Strings (Entropy Detection) ──────────────
//    These are random-looking strings with entropy > 4.5 bits
const dbPassword = "xK9#mP2$vL8nQ4@rT6wY";
const sessionToken = "a8F3kLmN9pQrStUvWxYz2B4C6D";
const encryptKey = "3f2a1b8e7d6c5f4a9b0e8d7c6f5e4d3c";
const jwtSecret = "mZq4t7w!z%C*F-JaNdRgUkXp2s5v8y/B";


// ── 10. Mixed in code context (realistic scenario) ───────────
function connectToDatabase() {
    return {
        host: "db.production.internal",
        user: "admin",
        password: "Pr0duct10n@SecretKey#2024",
        apiToken: "AKIAIOSFODNN7EXAMPLE",
    };
}

const config = {
    services: {
        stripe: { key: "sk_live_abcdefghijklmnopqrstuvwxyz123456" },
        sendgrid: { api_key: "SG.abcdefghijklmnop.ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
        firebase: { secret: "firebase_secret_key_abcdefghijklmnopqrst" },
    }
};
