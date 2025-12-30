# GitHub Secrets Setup Guide

## Why Use GitHub Secrets?

GitHub Secrets allow you to:
- Store your VirusTotal API key securely
- Use the key in GitHub Actions workflows
- Never expose the key in public repositories
- Easily rotate keys without changing code

## Setting Up Your API Key in GitHub Secrets

### Step 1: Navigate to Repository Settings

1. Go to https://github.com/wyms/sitecapture
2. Click on **Settings** (top right, near the tabs)
3. In the left sidebar, click **Secrets and variables** → **Actions**

### Step 2: Add New Repository Secret

1. Click the **New repository secret** button
2. Fill in the details:
   - **Name**: `VIRUSTOTAL_API_KEY`
   - **Value**: `5c1409fec5df4b4f6740e25d638007a27a69c06808f53c4794ce11a46ec31c43`
3. Click **Add secret**

### Step 3: Verify Secret is Added

You should see `VIRUSTOTAL_API_KEY` in your list of secrets with:
- Green checkmark indicating it's set
- Updated timestamp
- Option to update or remove

**Note:** GitHub will never show you the secret value again after saving for security reasons.

## Using Secrets in GitHub Actions

If you create automated workflows, access the secret like this:

```yaml
name: Scan Website

on:
  workflow_dispatch:
    inputs:
      url:
        description: 'URL to scan'
        required: true

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: pip install -r requirements.txt

    - name: Scan website
      env:
        VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
      run: |
        python site_cloner.py ${{ github.event.inputs.url }} --scan -d 1

    - name: Upload results
      uses: actions/upload-artifact@v3
      with:
        name: scan-results
        path: clone_*
```

## Security Best Practices

### ✓ DO:
- Use GitHub Secrets for all API keys
- Rotate API keys periodically
- Use separate keys for production and testing
- Review who has access to repository secrets

### ✗ DON'T:
- Never commit API keys to git
- Never print secrets in logs (`echo $VIRUSTOTAL_API_KEY`)
- Never share secrets in pull request comments
- Never hardcode secrets in code

## Local Development vs GitHub

### Local Development (.env file):
```bash
# .env file (NOT committed to git)
VIRUSTOTAL_API_KEY=your_key_here
```

### GitHub Actions (Secrets):
```yaml
env:
  VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
```

### Both work with the same code!
The `site_cloner.py` checks in this order:
1. Command line argument: `--vt-api-key`
2. Environment variable: `VIRUSTOTAL_API_KEY`
3. .env file: `VIRUSTOTAL_API_KEY=...`

## Managing Multiple Keys

If you need different keys for different purposes:

```yaml
# In GitHub Secrets, create:
VIRUSTOTAL_API_KEY_PROD    # For production scans
VIRUSTOTAL_API_KEY_TEST    # For testing
VIRUSTOTAL_API_KEY_BACKUP  # Backup key
```

Then in workflows:
```yaml
env:
  VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY_PROD }}
```

## Troubleshooting

### "Secret not found" in GitHub Actions

1. Check the secret name matches exactly (case-sensitive)
2. Verify the secret is set in the correct repository
3. Ensure the workflow has permission to access secrets

### Secret not working locally

GitHub Secrets only work in GitHub Actions, not locally. For local development:
- Use `.env` file
- Or set environment variable: `export VIRUSTOTAL_API_KEY=your_key`

### Want to update the secret?

1. Go to repository Settings → Secrets
2. Click on `VIRUSTOTAL_API_KEY`
3. Click **Update secret**
4. Enter new value
5. Click **Update secret**

## API Key Rotation

To rotate your API key:

1. Get new key from VirusTotal
2. Update GitHub Secret with new key
3. Update local `.env` file with new key
4. Old key can be deactivated in VirusTotal

## Additional Resources

- [GitHub Secrets Documentation](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [VirusTotal API Key Management](https://www.virustotal.com/gui/user/[username]/apikey)
- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
