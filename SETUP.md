# Setup Guide

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/wyms/sitecapture.git
cd sitecapture
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Key (Optional - for virus scanning)

**Method 1: Using .env file (Recommended)**

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your VirusTotal API key
# VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

**Method 2: Environment Variable**

Windows:
```bash
setx VIRUSTOTAL_API_KEY "your_api_key_here"
```

Linux/Mac:
```bash
export VIRUSTOTAL_API_KEY=your_api_key_here
```

**Method 3: Command Line**

```bash
python site_cloner.py https://example.com --scan --vt-api-key your_api_key_here
```

### 4. Test the Installation

```bash
# Basic test without scanning
python site_cloner.py https://example.com -d 0

# Test with virus scanning (requires API key)
python site_cloner.py https://example.com -d 0 --scan
```

## Getting a VirusTotal API Key

1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for a free account
3. Verify your email
4. Go to your profile and copy your API key

**Free Tier Limits:**
- 4 requests per minute
- 500 requests per day
- Hash-based lookups (no file uploads)

## Security Best Practices

### IMPORTANT: Never Commit Your API Key!

The `.gitignore` file is configured to exclude:
- `.env` files
- API key files
- Clone output directories

**Always:**
- Use `.env` file for local development
- Use GitHub Secrets for CI/CD
- Never hardcode API keys in code
- Never commit `.env` to git

### For GitHub Actions / CI/CD

If you want to run automated scans:

1. Go to your repo settings: `https://github.com/wyms/sitecapture/settings/secrets`
2. Click "New repository secret"
3. Name: `VIRUSTOTAL_API_KEY`
4. Value: Your actual API key
5. Click "Add secret"

Then in GitHub Actions workflows, access it with:
```yaml
env:
  VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
```

## Troubleshooting

### "API key not found" error

Make sure:
- `.env` file exists and contains `VIRUSTOTAL_API_KEY=your_key`
- No quotes around the key in `.env`
- The `.env` file is in the same directory as `site_cloner.py`

### "Permission denied" when running

Windows:
```bash
python site_cloner.py https://example.com
```

Linux/Mac (make executable):
```bash
chmod +x site_cloner.py
./site_cloner.py https://example.com
```

### Import errors

Make sure all dependencies are installed:
```bash
pip install -r requirements.txt
```

## Next Steps

- Read [QUICK_START.md](QUICK_START.md) for usage examples
- Read [VIRUS_SCANNING_GUIDE.md](VIRUS_SCANNING_GUIDE.md) for detailed scanning info
- Read [README.md](README.md) for full documentation
