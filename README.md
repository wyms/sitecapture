# Website Cloner - Documentation & Archival Tool

A Python application for creating local clones of websites for documentation, evidence preservation, and fraud prevention purposes.

[![GitHub Repository](https://img.shields.io/badge/GitHub-wyms%2Fsitecapture-blue?logo=github)](https://github.com/wyms/sitecapture)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Quick Links

- 🚀 [Quick Start Guide](QUICK_START.md)
- 🔒 [GitHub Secrets Setup](GITHUB_SECRETS.md)
- 🛡️ [Virus Scanning Guide](VIRUS_SCANNING_GUIDE.md)
- ⚙️ [Detailed Setup](SETUP.md)

## Purpose

In an age where online fraud is prevalent, this tool helps document and preserve website content for legitimate purposes such as:

- Evidence preservation for fraud investigation
- Documentation of misleading claims or false advertising
- Archival of website content before it's altered or removed
- Record-keeping for legal proceedings
- Consumer protection and accountability

## Features

- **Complete Page Cloning**: Downloads HTML pages with all resources (images, CSS, JavaScript)
- **Virus Scanning**: Optional integration with VirusTotal to scan downloaded files for malware
- **Depth Control**: Configure how deep to crawl through linked pages
- **Domain Filtering**: Option to stay within the same domain or follow external links
- **Integrity Verification**: SHA256 hashes for all downloaded files
- **Metadata Tracking**: JSON file with complete clone information including timestamps
- **Easy Navigation**: Auto-generated index page for viewing archived content
- **Progress Tracking**: Real-time console output showing clone progress

## Installation

### From GitHub

```bash
git clone https://github.com/wyms/sitecapture.git
cd sitecapture
pip install -r requirements.txt
```

### API Key Setup

Copy `.env.example` to `.env` and add your VirusTotal API key:

```bash
cp .env.example .env
# Edit .env and add: VIRUSTOTAL_API_KEY=your_key_here
```

Get a free API key at: https://www.virustotal.com/gui/join-us

For GitHub deployment, see [GitHub Secrets Setup](GITHUB_SECRETS.md)

## Usage

### Basic Usage

Clone a website with default settings (depth 3, same domain only):

```bash
python site_cloner.py https://example.com
```

### Advanced Options

```bash
# Specify output directory
python site_cloner.py https://example.com -o my_archive

# Set maximum crawl depth
python site_cloner.py https://example.com -d 2

# Allow resources from other domains
python site_cloner.py https://example.com --all-domains

# Combine options
python site_cloner.py https://example.com -o fraud_evidence -d 1 --all-domains
```

### Virus Scanning (Optional but Recommended)

For fraud documentation, it's highly recommended to enable virus scanning to detect malware that fraudulent sites may contain:

```bash
# Enable virus scanning with VirusTotal
python site_cloner.py https://suspicious-site.com --scan --vt-api-key YOUR_API_KEY

# Or set environment variable first
set VIRUSTOTAL_API_KEY=your_key_here
python site_cloner.py https://suspicious-site.com --scan
```

**Getting a VirusTotal API Key (Free):**
1. Visit https://www.virustotal.com/gui/join-us
2. Create a free account
3. Go to your profile and copy your API key
4. Free tier allows 4 requests per minute

**Note:** Virus scanning adds ~15 seconds per file due to API rate limits, but provides critical security information.

### Command Line Arguments

- `url` - Website URL to clone (required)
- `-o, --output` - Output directory (default: auto-generated with timestamp)
- `-d, --depth` - Maximum crawl depth (default: 3)
- `--all-domains` - Allow cloning resources from other domains
- `--scan` - Enable virus scanning of downloaded files
- `--vt-api-key` - VirusTotal API key (or set VIRUSTOTAL_API_KEY environment variable)

## Output Structure

After cloning, you'll get:

```
clone_example_com_20231229_143022/
├── index.html                    # Navigation page for the archive
├── clone_metadata.json           # Complete metadata with hashes
└── example.com/
    ├── index.html
    ├── about/
    │   └── index.html
    └── assets/
        ├── style.css
        └── images/
            └── logo.png
```

### Metadata File

The `clone_metadata.json` includes:

- Original URL and clone timestamp
- List of all cloned pages with SHA256 hashes
- Downloaded resources with file sizes and content types
- Failed downloads with error messages
- Summary statistics
- Virus scan results (if scanning enabled):
  - Number of antivirus engines that flagged each file
  - Malicious vs suspicious classifications
  - Detailed scan results for each file

## Legal and Ethical Considerations

**IMPORTANT**: This tool is for legitimate purposes only.

### Allowed Uses

- Documenting fraud or false claims
- Evidence preservation for legal proceedings
- Personal archival of publicly accessible content
- Research and analysis with proper authorization
- Consumer protection documentation

### Best Practices

1. **Respect robots.txt**: Check if the site allows automated access
2. **Rate Limiting**: Don't overwhelm servers; use appropriate depth settings
3. **Legal Compliance**: Ensure your use complies with applicable laws
4. **Terms of Service**: Review and respect website ToS
5. **Privacy**: Don't archive private or sensitive information without authorization
6. **Attribution**: Maintain accurate records of sources and timestamps

### What NOT to Do

- Don't use for unauthorized access or bypass security measures
- Don't republish copyrighted content without permission
- Don't use to harm legitimate businesses
- Don't overwhelm servers with excessive requests
- Don't archive private data or violate privacy laws

## Use Cases

### Fraud Documentation with Virus Scanning

When encountering potential fraud, enable virus scanning to detect malware:

```bash
# Clone with virus scanning enabled
python site_cloner.py https://suspicious-site.com -d 1 -o fraud_evidence_2023 --scan --vt-api-key YOUR_KEY
```

The tool will:
1. Create timestamped archive
2. Generate SHA256 hashes for integrity
3. Scan all downloaded files with 70+ antivirus engines via VirusTotal
4. Flag any malicious or suspicious content
5. Save metadata for legal documentation
6. Preserve content exactly as it appeared

**Why virus scanning matters for fraud documentation:**
- Fraudulent sites often distribute malware alongside scams
- Documenting malware presence strengthens evidence
- Protects investigators from accidentally executing malicious code
- Provides technical proof of malicious intent

### Before/After Comparison

Clone a site, wait for changes, then clone again to document alterations:

```bash
python site_cloner.py https://example.com -o before_clone
# Wait for changes
python site_cloner.py https://example.com -o after_clone
```

## Technical Details

- **HTML Parsing**: BeautifulSoup4 with lxml parser
- **HTTP Requests**: requests library with session pooling
- **Hash Algorithm**: SHA256 for file integrity
- **Encoding**: UTF-8 for all text files
- **Supported Resources**: HTML, CSS, JS, images, videos, audio
- **Virus Scanning**: VirusTotal API v3 with hash-based lookups
  - Scans using 70+ antivirus engines
  - Hash-only lookups (no file uploads with free tier)
  - Rate limited to 4 requests/minute (free tier)

## Troubleshooting

### Connection Errors

If you encounter connection errors:
- Check your internet connection
- Verify the URL is correct and accessible
- Some sites may block automated access
- Try reducing depth with `-d 1`

### Missing Resources

If some resources aren't downloaded:
- Try `--all-domains` flag for cross-domain resources
- Check the `clone_metadata.json` for failed downloads
- Some resources may require authentication

### Large Sites

For large sites:
- Reduce depth with `-d 1` or `-d 2`
- Clone specific sections instead of the entire site
- Monitor disk space during cloning

### Virus Scanning Issues

If virus scanning fails:
- Verify your API key is correct
- Check you haven't exceeded rate limits (4/min free tier)
- Ensure internet connection is stable
- Files not in VirusTotal database will show as "unknown"
- Consider upgrading VirusTotal tier for file uploads and higher limits

## License

This tool is provided as-is for legitimate documentation and archival purposes. Users are responsible for ensuring their use complies with applicable laws and regulations.

## Disclaimer

This tool is intended for legal and ethical use only. The creators assume no liability for misuse. Always ensure you have appropriate authorization and comply with all applicable laws, regulations, and terms of service.
