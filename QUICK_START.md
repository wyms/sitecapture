# Quick Start Guide

## Basic Usage (No Virus Scanning)

Clone a website for documentation:

```bash
python site_cloner.py https://example.com
```

This will:
- Download the website and all resources
- Create a timestamped folder with the clone
- Generate SHA256 hashes for integrity
- Create an index.html for easy viewing

## With Virus Scanning (Recommended for Fraud Documentation)

### Step 1: Get a Free VirusTotal API Key

1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for a free account
3. Verify your email
4. Copy your API key from your profile

### Step 2: Set Your API Key

Windows:
```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
```

Linux/Mac:
```bash
export VIRUSTOTAL_API_KEY=your_api_key_here
```

### Step 3: Clone with Scanning

```bash
python site_cloner.py https://suspicious-site.com --scan -d 1
```

## Common Options

```bash
# Limit depth (faster)
python site_cloner.py https://example.com -d 1

# Specify output folder
python site_cloner.py https://example.com -o my_evidence

# Enable virus scanning
python site_cloner.py https://example.com --scan

# Full fraud documentation
python site_cloner.py https://fraud-site.com --scan -d 1 -o fraud_evidence_2025
```

## What You'll Get

After running, you'll have a folder containing:

- `index.html` - View the archived site
- `clone_metadata.json` - All technical details, hashes, and scan results
- Complete copy of the website with all resources

## Important Notes

- Virus scanning adds ~15 seconds per file (API rate limits)
- Free VirusTotal tier: 4 requests/minute, 500/day
- Files are scanned by 70+ antivirus engines
- All results saved in metadata for legal documentation

## Need Help?

- See `README.md` for full documentation
- See `VIRUS_SCANNING_GUIDE.md` for detailed scanning info
- Run `python site_cloner.py --help` for all options
