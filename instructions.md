# 📘 GitGuard: Setup, Migration & Testing Guide

This guide provides end-to-end instructions for:
1. **Creating and configuring your GitHub App**
2. **Deploying / shifting the infrastructure to a different AWS account**
3. **Testing the entire pipeline (Unit tests, Webhook Replay, and Live GitHub PR tests)**

---

## 📑 Table of Contents

- [Architecture Overview](#-architecture-overview)
- [Part 1: Create and Configure the GitHub App](#-part-1-create-and-configure-the-github-app)
  - [1.1 Generate a Secure Webhook Secret](#11-generate-a-secure-webhook-secret)
  - [1.2 Register the GitHub App](#12-register-the-github-app)
  - [1.3 Configure Permissions and Events](#13-configure-permissions-and-events)
  - [1.4 Generate and Download the Private Key](#14-generate-and-download-the-private-key)
  - [1.5 Install the App on Target Repositories](#15-install-the-app-on-target-repositories)
- [Part 2: Shift / Deploy to a Different AWS Account](#-part-2-shift--deploy-to-a-different-aws-account)
  - [2.1 Prerequisites & Tooling](#21-prerequisites--tooling)
  - [2.2 Configure Target AWS Account Credentials](#22-configure-target-aws-account-credentials)
  - [2.3 Enable Amazon Bedrock Model Access](#23-enable-amazon-bedrock-model-access)
  - [2.4 Store Secrets in AWS Secrets Manager](#24-store-secrets-in-aws-secrets-manager)
  - [2.5 Build and Deploy Infrastructure using AWS SAM](#25-build-and-deploy-infrastructure-using-aws-sam)
  - [2.6 Update GitHub App Webhook URL](#26-update-github-app-webhook-url)
  - [2.7 (Optional) Clean Up Resources from Old AWS Account](#27-optional-clean-up-resources-from-old-aws-account)
- [Part 3: Testing & Verification](#-part-3-testing--verification)
  - [3.1 Layer 1: Run Local Unit Tests](#31-layer-1-run-local-unit-tests)
  - [3.2 Layer 2: Test Endpoint with Webhook Replay Script](#32-layer-2-test-endpoint-with-webhook-replay-script)
  - [3.3 Layer 3: Live End-to-End Test on GitHub](#33-layer-3-live-end-to-end-test-on-github)
  - [3.4 Verify DynamoDB and CloudWatch Logs](#34-verify-dynamodb-and-cloudwatch-logs)
- [Part 4: Troubleshooting Common Issues](#-part-4-troubleshooting-common-issues)

---

## 🏛️ Architecture Overview

```
GitHub Pull Request Event (opened / synchronize / reopened)
              │
              ▼
   GitHub App (Webhook)
              │  POST /webhook (HMAC-SHA256 signed)
              ▼
   AWS API Gateway (HTTP API)
              │
              ▼
   Ingest Lambda (Python 3.12, 10s timeout)
   ├── 1. Verify HMAC-SHA256 signature using webhook_secret from Secrets Manager
   ├── 2. Check event type (pull_request) and action (opened, synchronize, reopened)
   ├── 3. Enforce idempotency via DynamoDB conditional put (PK: EVENT#<delivery_id>)
   └── 4. Asynchronously invoke Worker Lambda (InvocationType='Event')
              │
              ▼
   Worker Lambda (Python 3.12, 5m timeout)
   ├── 1. Generate RS256 JWT using app_id & private_key from Secrets Manager
   ├── 2. Exchange JWT for short-lived GitHub Installation Token (1h TTL)
   ├── 3. Fetch changed PR files & unified diffs via GitHub REST API
   ├── 4. Parse unified diffs line-by-line & map additions to line numbers
   ├── 5. Invoke Amazon Bedrock (Amazon Nova Micro) with anti-injection prompt
   ├── 6. Validate JSON output against strict schema & eliminate hallucinations
   ├── 7. Post consolidated GitHub PR Review with inline comments
   └── 8. Store audit findings and delivery status in DynamoDB (TTL 90 days)
```

---

## 🐙 Part 1: Create and Configure the GitHub App

### 1.1 Generate a Secure Webhook Secret

Before creating the app, generate a high-entropy secret string to protect your webhook endpoint against spoofing.

**PowerShell:**
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 40 | ForEach-Object {[char]$_})
```

**Bash / Linux / macOS:**
```bash
openssl rand -hex 20
```

> 💡 *Save this secret temporarily in a secure note; you will need it in GitHub and AWS Secrets Manager.*

---

### 1.2 Register the GitHub App

1. Sign in to GitHub and navigate to:
   - **Personal Account**: [github.com/settings/apps](https://github.com/settings/apps)
   - **Organization**: `https://github.com/organizations/<your-org>/settings/apps`
2. Click **New GitHub App**.
3. Fill in the **Basic information**:
   - **GitHub App name**: `GitGuard-Security-Auditor` *(must be unique across GitHub)*
   - **Homepage URL**: `https://github.com` (or your repository URL)
4. Configure **Webhook**:
   - Check **Active**.
   - **Webhook URL**: Enter a temporary placeholder URL (e.g. `https://example.com/webhook`). *You will update this with the real AWS API Gateway URL after deploying to AWS.*
   - **Webhook secret**: Paste the random secret generated in [Section 1.1](#11-generate-a-secure-webhook-secret).
   - **SSL verification**: Select **Enable SSL verification**.

---

### 1.3 Configure Permissions and Events

Scroll down to the **Permissions** section and configure:

#### Repository Permissions:
| Permission | Access | Reason |
| :--- | :--- | :--- |
| **Pull requests** | **Read and write** | Required to fetch PR file diffs and submit review comments |
| **Contents** | **Read-only** | Required to read repository file contents if necessary |
| **Metadata** | **Read-only** | Automatically selected by GitHub (mandatory for all apps) |

#### Subscribe to Events:
Under **Subscribe to events**, check:
- [x] **Pull request**

#### Installation Availability:
- Choose **Only on this account** (recommended for internal use) or **Any account**.

Click **Create GitHub App**.

---

### 1.4 Generate and Download the Private Key

1. On the app summary page, note the **App ID** (an integer such as `1234567`).
2. Scroll down to the **Private keys** section.
3. Click **Generate a private key**.
4. A `.pem` file will automatically download to your computer (e.g., `gitguard-security-auditor.2026-10-14.private-key.pem`).
5. **Keep this file secure!** You will store its contents in AWS Secrets Manager in Part 2.

---

### 1.5 Install the App on Target Repositories

1. In the left sidebar of your GitHub App settings, click **Install App**.
2. Click **Install** next to your user account or organization.
3. Select **Only select repositories** and pick the repository you want GitGuard to audit.
4. Click **Install**.
5. After installing, check the URL in your browser:
   `https://github.com/settings/installations/12345678`
   The trailing number (`12345678`) is your **Installation ID**. Keep this handy for direct replay testing.

---

## ☁️ Part 2: Shift / Deploy to a Different AWS Account

### 2.1 Prerequisites & Tooling

Ensure the following tools are installed on your machine:
- **Python 3.12+**: `python --version`
- **AWS CLI**: `aws --version`
- **AWS SAM CLI**: `sam --version`

---

### 2.2 Configure Target AWS Account Credentials

To shift deployments to a new AWS account, switch your active AWS credentials to the new account.

#### Option A: Using AWS CLI Profiles (Recommended)

1. Run the configure wizard for a named profile:
   ```bash
   aws configure --profile new-account
   ```
2. Enter:
   - **AWS Access Key ID**: Access key of an IAM user/role in the *new* account (requires administrator or deployment permissions).
   - **AWS Secret Access Key**: Corresponding secret key.
   - **Default region name**: e.g., `ap-south-1` or `us-east-1`.
   - **Default output format**: `json`.

3. Set the active profile:
   - **PowerShell:**
     ```powershell
     $env:AWS_PROFILE = "new-account"
     $env:AWS_DEFAULT_REGION = "ap-south-1"
     ```
   - **Bash / Linux / macOS:**
     ```bash
     export AWS_PROFILE=new-account
     export AWS_DEFAULT_REGION=ap-south-1
     ```

#### Option B: Using Direct Environment Variables

- **PowerShell:**
  ```powershell
  $env:AWS_ACCESS_KEY_ID = "YOUR_NEW_ACCOUNT_ACCESS_KEY"
  $env:AWS_SECRET_ACCESS_KEY = "YOUR_NEW_ACCOUNT_SECRET_KEY"
  $env:AWS_DEFAULT_REGION = "ap-south-1"  # or us-east-1
  ```
- **Bash / Linux / macOS:**
  ```bash
  export AWS_ACCESS_KEY_ID="YOUR_NEW_ACCOUNT_ACCESS_KEY"
  export AWS_SECRET_ACCESS_KEY="YOUR_NEW_ACCOUNT_SECRET_KEY"
  export AWS_DEFAULT_REGION="ap-south-1"
  ```

#### Verify Active Account Identity:
Always verify you are interacting with the new account before proceeding:
```bash
aws sts get-caller-identity
```
Ensure the `Account` value in the output matches your **new target AWS Account ID**.

---

### 2.3 Enable Amazon Bedrock Model Access

GitGuard uses **Amazon Nova Micro** (or foundation models like Claude or Nova Lite) on Amazon Bedrock.

1. Log in to the AWS Management Console of the **new AWS account**.
2. Switch to your desired AWS Region (e.g. `ap-south-1` for Mumbai, or `us-east-1` for N. Virginia).
3. Search for **Amazon Bedrock**.
4. In the left navigation menu, click **Model access** (under *Foundation models*).
5. Ensure access to **Amazon Nova Micro** (or your preferred foundation model) is enabled:
   - If not enabled, click **Modify model access** or **Enable all models**, accept EULA terms, and save.
   - *Note: Amazon Nova models use cross-region inference profiles such as `apac.amazon.nova-micro-v1:0` (in APAC) or `us.amazon.nova-micro-v1:0` (in US).*

---

### 2.4 Store Secrets in AWS Secrets Manager

The Ingest and Worker Lambdas require access to:
- `app_id`: GitHub App ID (string or number)
- `webhook_secret`: The secret string configured in Section 1.1
- `private_key`: The RSA private key from the downloaded `.pem` file

#### Preparing the Secret JSON:
The JSON stored in Secrets Manager must match this structure:
```json
{
  "app_id": "1234567",
  "webhook_secret": "your_secure_webhook_secret_here",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
}
```

> [!IMPORTANT]
> The private key in the JSON must include all headers, footers, and replace physical line breaks with `\n`.

#### Automated Script to Create the Secret (PowerShell):

Run this PowerShell script from the directory containing your `.pem` file:

```powershell
$AppId = "YOUR_GITHUB_APP_ID"
$WebhookSecret = "YOUR_WEBHOOK_SECRET"
$PemPath = "path\to\your-downloaded-private-key.pem"
$Region = "ap-south-1"

# Read PEM file and replace CRLF/LF with \n
$PemContent = (Get-Content $PemPath -Raw) -replace "\r?\n", "\n"

# Build JSON payload
$SecretPayload = @{
    app_id = $AppId
    webhook_secret = $WebhookSecret
    private_key = $PemContent
} | ConvertTo-Json -Compress

# Create Secret in AWS Secrets Manager
aws secretsmanager create-secret `
    --name "github-security-auditor-secret" `
    --description "Credentials for GitGuard GitHub App" `
    --secret-string "$SecretPayload" `
    --region $Region
```

#### Automated Script to Create the Secret (Bash):

```bash
APP_ID="YOUR_GITHUB_APP_ID"
WEBHOOK_SECRET="YOUR_WEBHOOK_SECRET"
PEM_PATH="./your-downloaded-private-key.pem"
REGION="ap-south-1"

python -c '
import sys, json
app_id, secret, pem_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(pem_path, "r") as f:
    key_data = f.read()
payload = {"app_id": app_id, "webhook_secret": secret, "private_key": key_data}
with open("secret_payload.json", "w") as out:
    json.dump(payload, out)
' "$APP_ID" "$WEBHOOK_SECRET" "$PEM_PATH"

aws secretsmanager create-secret \
    --name "github-security-auditor-secret" \
    --description "Credentials for GitGuard GitHub App" \
    --secret-string file://secret_payload.json \
    --region $REGION

rm secret_payload.json
```

#### Save the Returned Secret ARN:
The command outputs a JSON object containing `ARN`:
```text
arn:aws:secretsmanager:ap-south-1:112233445566:secret:github-security-auditor-secret-xYz123
```
Copy this ARN. You will pass it to the SAM deployment command.

---

### 2.5 Build and Deploy Infrastructure using AWS SAM

1. Navigate to the root of the GitReviewSecutiryAuditor repository:
   ```bash
   cd c:\Users\himal\Documents\Projects\GitReviewSecutiryAuditor
   ```

2. **Build the Lambda artifacts:**
   ```bash
   sam build
   ```

3. **Deploy the stack to the new AWS account:**

   **Interactive deployment (`--guided`):**
   ```bash
   sam deploy --guided
   ```
   **Parameters to enter:**
   - **Stack Name**: `git-security-auditor`
   - **AWS Region**: `ap-south-1` (or your chosen region)
   - **Parameter GitHubSecretArn**: `<paste your Secrets Manager ARN from Section 2.4>`
   - **Parameter BedrockModelId**: `apac.amazon.nova-micro-v1:0` (use `us.amazon.nova-micro-v1:0` if deploying in `us-east-1` or `us-west-2`)
   - **Parameter MaxDiffSize**: `100000`
   - **Confirm changes before deploy**: `N`
   - **Allow SAM CLI IAM role creation**: `Y`
   - **Disable rollback for faster debugging**: `N`
   - **Save arguments to configuration file**: `Y` (writes to `samconfig.toml`)

   **Alternatively, direct automated deployment (PowerShell):**
   ```powershell
   sam deploy `
     --stack-name git-security-auditor `
     --region ap-south-1 `
     --capabilities CAPABILITY_IAM `
     --parameter-overrides GitHubSecretArn="<YOUR_SECRET_ARN>" BedrockModelId="apac.amazon.nova-micro-v1:0" `
     --resolve-s3
   ```

4. **Verify the Deployment Outputs:**
   At the end of the deployment, SAM prints the CloudFormation Outputs:
   ```text
   Outputs
   -------------------------------------------------------------------------------------------------
   Key                 WebhookEndpoint
   Description         HTTP API endpoint URL to configure in GitHub Webhook settings
   Value               https://abc123xyz.execute-api.ap-south-1.amazonaws.com/webhook

   Key                 SecurityAuditTableName
   Description         Name of DynamoDB table storing audit results
   Value               git-security-auditor-SecurityAudit
   -------------------------------------------------------------------------------------------------
   ```
   Copy the `WebhookEndpoint` URL.

---

### 2.6 Update GitHub App Webhook URL

1. Go back to your GitHub App settings page on GitHub.
2. Under **General** → **Webhook**:
   - Replace the placeholder **Webhook URL** with your newly deployed `WebhookEndpoint`:
     `https://abc123xyz.execute-api.ap-south-1.amazonaws.com/webhook`
   - Ensure the **Webhook secret** matches the secret you stored in Secrets Manager.
3. Click **Save changes**.

---

### 2.7 (Optional) Clean Up Resources from Old AWS Account

If you want to tear down the old resources in the previous account to avoid unnecessary charges:

1. Switch credentials back to the old AWS account:
   ```powershell
   $env:AWS_PROFILE = "old-account"
   ```
2. Delete the CloudFormation stack:
   ```bash
   sam delete --stack-name git-security-auditor --region ap-south-1
   ```
3. Delete the Secrets Manager secret in the old account:
   ```bash
   aws secretsmanager delete-secret \
     --secret-id "github-security-auditor-secret" \
     --force-delete-without-recovery \
     --region ap-south-1
   ```

---

## 🧪 Part 3: Testing & Verification

We use a 3-layer testing strategy:

```
┌────────────────────────────────────────────────────────┐
│ Layer 1: Local Unit Tests (Mocked AWS & GitHub APIs)    │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Layer 2: Webhook Replay Script (Direct HTTP API Test)  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│ Layer 3: Live End-to-End Test (Real PR on GitHub)      │
└────────────────────────────────────────────────────────┘
```

---

### 3.1 Layer 1: Run Local Unit Tests

Verify that all Python modules, diff parsers, HMAC validators, and review generators pass locally:

```bash
# 1. Install local test requirements
pip install -r tests/requirements.txt
# (or: pip install pytest boto3 requests pyjwt cryptography)

# 2. Run the test suite
python -m pytest -v
# (or simply: pytest -v)
```

Expected output:
```text
tests/test_diffparse.py::test_parse_numbered_diff_standard PASSED
tests/test_diffparse.py::test_should_skip_file PASSED
...
tests/test_ingest.py::test_valid_hmac_accepted PASSED
tests/test_ingest.py::test_invalid_hmac_rejected PASSED
...
tests/test_validation.py::test_filter_hallucinated_lines PASSED
tests/test_review.py::test_build_review_payload PASSED

============================== 24 passed in 0.85s ==============================
```

---

### 3.2 Layer 2: Test Endpoint with Webhook Replay Script

Use the built-in CLI tool in `scripts/replay_webhook.py` to send a cryptographically signed HMAC payload directly to your live API Gateway endpoint:

```bash
python scripts/replay_webhook.py \
  --url "https://abc123xyz.execute-api.ap-south-1.amazonaws.com/webhook" \
  --secret "YOUR_WEBHOOK_SECRET" \
  --repo "your-username/your-repo" \
  --pr 1 \
  --sha "6dcb09b5b57875f334f61aebed695e2e4193db5e" \
  --installation-id 12345678
```

#### What to expect:
```text
📡 Sending mock webhook event to: https://abc123xyz.execute-api.ap-south-1.amazonaws.com/webhook
📦 Repository: your-username/your-repo | PR #1 | Delivery: test-replay-1728919000

Status Code: 202
Response Body:
{"message":"Accepted and queued for processing"}

✅ Webhook successfully accepted and queued for worker processing!
```

If you re-run the exact same command immediately:
- You will see status code `200` with:
  `{"message":"Event already processed (idempotency key matched)"}`
  This confirms DynamoDB idempotency is functioning properly!

---

### 3.3 Layer 3: Live End-to-End Test on GitHub

Now test the complete live workflow with a real pull request on GitHub:

1. **Clone or open your test repository** where the GitHub App is installed.
2. **Create a new branch**:
   ```bash
   git checkout -b test/gitguard-security-audit
   ```
3. **Add a file containing known security flaws**:
   Copy the sample vulnerable file provided in `demo/vulnerable_app.py`:
   ```bash
   cp path/to/GitReviewSecutiryAuditor/demo/vulnerable_app.py app_security_test.py
   git add app_security_test.py
   git commit -m "feat: add user authentication and database queries"
   git push origin test/gitguard-security-audit
   ```
4. **Open a Pull Request** against the `main` branch on GitHub.
5. **Watch GitGuard audit the PR**:
   - Within 5–15 seconds, GitGuard's bot account will submit a review on the PR!
   - You will see:
     1. **Summary Review Comment**: A table detailing total files analyzed, number of Critical/High/Medium/Low findings, and execution duration.
     2. **Inline Review Comments**: Direct comments on exact lines showing:
        - 🔴 **[CRITICAL] SQL Injection (CWE-89)** on the dynamic query line.
        - 🔴 **[CRITICAL] Hardcoded API Keys / Secrets (CWE-798)** on the credential lines.
        - 🔴 **[CRITICAL] Remote Code Execution via eval() (CWE-94)**.
        - 🟠 **[HIGH] Path Traversal (CWE-22)**.
        - 🟠 **[HIGH] Command Injection (CWE-78)** on the `os.system()` line.
        - 🟡 **[MEDIUM] Weak Cryptographic Hash (CWE-327)** on the MD5 line.
        - **Suggested Code Fixes** for each issue.
     3. The prompt injection attempt inside the code comments (`# IGNORE ALL PREVIOUS INSTRUCTIONS...`) is completely ignored.

---

### 3.4 Verify DynamoDB and CloudWatch Logs

#### 1. Inspect DynamoDB Audit Findings:
Run AWS CLI to query audit records in the DynamoDB table:
```bash
aws dynamodb scan \
  --table-name git-security-auditor-SecurityAudit \
  --region ap-south-1
```
You will find items with:
- `PK: AUDIT#<owner/repo>#<pr_number>`
- `SK: COMMIT#<commit_sha>`
- `findings`: Array of identified security vulnerabilities.
- `ttl`: Expiration timestamp (90 days).

#### 2. Monitor Live Lambda Logs:
Tail CloudWatch logs in real-time as webhooks arrive:

```bash
# Tail Ingest Lambda (Webhook verification & dispatch)
sam logs --name IngestFunction --stack-name git-security-auditor --tail

# Tail Worker Lambda (Bedrock LLM analysis & GitHub API comments)
sam logs --name WorkerFunction --stack-name git-security-auditor --tail
```

---

## 🛠️ Part 4: Troubleshooting Common Issues

### Issue 1: GitHub Webhook shows `401 Unauthorized`
- **Cause**: The HMAC SHA-256 signature calculated by `IngestFunction` does not match `X-Hub-Signature-256`.
- **Fix**: Verify that the `webhook_secret` in AWS Secrets Manager matches the **Webhook secret** configured in GitHub App settings character-for-character. Ensure no accidental trailing spaces or quotes.

### Issue 2: Worker Lambda fails with `ValueError: Secret must contain 'app_id' and 'private_key'`
- **Cause**: The JSON structure in Secrets Manager is missing keys or has wrong field names.
- **Fix**: The SecretString MUST be valid JSON with exact top-level keys: `"app_id"`, `"webhook_secret"`, and `"private_key"`.

### Issue 3: GitHub API returns `401 Bad credentials` during token exchange
- **Cause**: Private key format issue or system clock skew.
- **Fix**:
  1. Ensure the private key in Secrets Manager preserves newlines (`\n`) and includes `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`.
  2. Verify your AWS Lambda environment time is synchronized (standard AWS Lambda handles this automatically).
  3. Ensure the App ID is correct.

### Issue 4: Bedrock returns `AccessDeniedException` or `ResourceNotFoundException`
- **Cause**: Amazon Bedrock model access is not enabled in the target region or account, or the model ID is invalid.
- **Fix**:
  1. Open AWS Console → Bedrock → **Model access** in your deployment region and verify that Amazon Nova Micro (or your chosen model) is granted.
  2. For `ap-south-1` (Mumbai), use inference profile: `apac.amazon.nova-micro-v1:0`.
  3. For `us-east-1` (N. Virginia), use inference profile: `us.amazon.nova-micro-v1:0`.

### Issue 5: GitHub API returns `422 Unprocessable Entity` when posting inline comments
- **Cause**: The diff line number is not part of the PR's unified diff additions (e.g. unmodified or deleted line).
- **Behavior & Fix**: GitGuard has built-in resilience: line numbers are validated against added lines, and if GitHub still rejects inline comments with `422`, Worker automatically falls back to posting all findings inside the top-level review body so no vulnerability alerts are lost.

---

## 📋 Summary Checklist

| Step | Action | Status |
| :--- | :--- | :---: |
| 1 | Generated random webhook secret | ⬜ |
| 2 | Created GitHub App with `Pull requests: Read & Write`, `Contents: Read-only` | ⬜ |
| 3 | Subscribed to `Pull request` events | ⬜ |
| 4 | Downloaded GitHub App RSA `.pem` private key & noted `App ID` | ⬜ |
| 5 | Installed GitHub App on target repository & noted `Installation ID` | ⬜ |
| 6 | Switched AWS CLI / environment to target AWS account (`aws sts get-caller-identity`) | ⬜ |
| 7 | Enabled Amazon Bedrock model access in the target region | ⬜ |
| 8 | Created AWS Secrets Manager secret with `app_id`, `webhook_secret`, and `private_key` | ⬜ |
| 9 | Ran `sam build` and `sam deploy` with `GitHubSecretArn` parameter | ⬜ |
| 10 | Updated GitHub App Webhook URL with SAM `WebhookEndpoint` output | ⬜ |
| 11 | Ran local tests (`pytest`) and `scripts/replay_webhook.py` test | ⬜ |
| 12 | Opened test PR with `demo/vulnerable_app.py` and verified bot review | ⬜ |
