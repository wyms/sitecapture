# Virus Scanning Guide

## Overview

The website cloner includes optional integration with VirusTotal, a service that scans files using 70+ antivirus engines. This is particularly important when archiving potentially fraudulent websites, as they often contain malware.

## Why Virus Scanning is Important

When documenting fraudulent websites:

1. **Evidence Collection**: Malware presence proves malicious intent
2. **Safety**: Protects investigators from accidentally executing malicious code
3. **Documentation**: Creates legal record of threats distributed by the site
4. **Pattern Detection**: Helps identify fraud networks using similar malware

## How It Works

The virus scanner uses VirusTotal's API to check files:

1. **Hash-Based Lookups**: Files are identified by their SHA256 hash
2. **No Uploads Required**: Free tier uses hash lookups only (files aren't uploaded)
3. **Multi-Engine Scanning**: Results from 70+ antivirus products
4. **Real-Time Results**: See scan results as files are downloaded

## Getting Started

### 1. Get a Free VirusTotal API Key

1. Visit https://www.virustotal.com/gui/join-us
2. Create a free account with your email
3. Verify your email address
4. Go to your profile settings
5. Copy your API key from the "API Key" section

**Free Tier Limits:**
- 4 requests per minute
- 500 requests per day
- Hash lookups only (no file uploads)

### 2. Set Your API Key

**Option A: Environment Variable (Recommended)**

Windows:
```bash
set VIRUSTOTAL_API_KEY=your_api_key_here
```

Linux/Mac:
```bash
export VIRUSTOTAL_API_KEY=your_api_key_here
```

To make it permanent on Windows, use:
```bash
setx VIRUSTOTAL_API_KEY "your_api_key_here"
```

**Option B: Command Line Argument**
```bash
python site_cloner.py https://example.com --scan --vt-api-key your_api_key_here
```

### 3. Run with Virus Scanning

```bash
python site_cloner.py https://suspicious-site.com --scan -d 1 -o fraud_evidence
```

## Understanding Scan Results

### Console Output

During scanning, you'll see:

```
  ✓ Downloaded resource: https://example.com/file.exe
    Scanning for threats...
    ⚠ THREAT DETECTED: 45 engines flagged as malicious, 3 as suspicious
```

Or for clean files:
```
  ✓ Downloaded resource: https://example.com/image.png
    Scanning for threats...
    ✓ Clean: 0/70 engines detected threats
```

### Metadata File

All scan results are saved in `clone_metadata.json`:

```json
{
  "pages_cloned": [
    {
      "url": "https://example.com/page.html",
      "sha256": "abc123...",
      "virus_scan": {
        "malicious": 0,
        "suspicious": 0,
        "total_engines": 70,
        "is_threat": false,
        "scan_date": "2025-12-29T12:00:00"
      }
    }
  ],
  "virus_scan_summary": {
    "total_scanned": 15,
    "threats_found": 2,
    "scan_results": [...]
  }
}
```

### Result Interpretation

- **Malicious**: File is confirmed malware by antivirus engine
- **Suspicious**: File exhibits suspicious behavior but not confirmed malware
- **Clean**: No threats detected
- **Unknown**: File not in VirusTotal database (may be new/unique)

**Threat Threshold:**
- 0 detections: Clean
- 1-3 detections: Possible false positive, investigate
- 4+ detections: Likely malicious
- 10+ detections: Definitely malicious

## Performance Considerations

### Rate Limiting

Free tier allows 4 requests per minute. The tool automatically:
- Waits 15 seconds between scans
- Respects API rate limits
- Continues if limits are hit

**Time Estimates:**
- 5 files: ~1.5 minutes
- 10 files: ~3 minutes
- 20 files: ~6 minutes
- 50 files: ~15 minutes

### Optimization Tips

1. **Limit Depth**: Use `-d 1` or `-d 0` to scan only essential pages
2. **Same Domain**: Keep `--all-domains` off to avoid scanning external resources
3. **Targeted Scanning**: Clone the suspicious pages first, not entire site

## Example Workflows

### Quick Fraud Documentation

Scan only the main page and immediate resources:

```bash
python site_cloner.py https://fraud-site.com --scan -d 0 -o evidence
```

### Comprehensive Investigation

Scan multiple levels with all resources:

```bash
python site_cloner.py https://fraud-site.com --scan -d 2 --all-domains -o full_evidence
```

### Batch Processing

Clone multiple sites (set API key first):

```bash
set VIRUSTOTAL_API_KEY=your_key
python site_cloner.py https://site1.com --scan -d 1 -o site1_evidence
python site_cloner.py https://site2.com --scan -d 1 -o site2_evidence
python site_cloner.py https://site3.com --scan -d 1 -o site3_evidence
```

## Troubleshooting

### "API Key Invalid" Error

- Double-check you copied the entire key
- Ensure no extra spaces in the key
- Verify your VirusTotal account is verified

### "Rate Limit Exceeded"

- Free tier: 4 requests/minute, 500/day
- Wait a few minutes and try again
- Consider upgrading VirusTotal tier for higher limits

### "File Not Found in Database"

- This is normal for unique/new files
- VirusTotal hasn't seen this exact file before
- File is saved with metadata showing "unknown" status
- Does not mean file is safe, just not yet scanned

### Slow Performance

- This is expected - 15 seconds per file due to rate limits
- Use `-d 0` or `-d 1` to scan fewer files
- Consider scanning only suspicious files manually

## Legal and Safety Considerations

### Safety Precautions

1. **Don't Execute Downloaded Files**: Even with scanning, don't run executables
2. **Isolated Environment**: Run the tool in a VM or isolated system
3. **Antivirus Protection**: Keep your local antivirus running
4. **Review Results**: Check metadata before examining downloaded files

### Evidence Handling

1. **Preserve Original**: Don't modify downloaded files
2. **Document Everything**: Metadata includes timestamps and hashes
3. **Chain of Custody**: Note who accessed files and when
4. **Legal Compliance**: Ensure your scanning complies with local laws

## Upgrading VirusTotal

For professional use, consider upgrading:

**Premium Tier Benefits:**
- 1,000 requests/minute (vs 4/minute)
- File uploads (up to 650MB)
- Advanced search capabilities
- Historical data access
- Priority support

Visit: https://www.virustotal.com/gui/user/[username]/apikey

## FAQ

**Q: Does scanning upload my files to VirusTotal?**
A: No, the free tier uses hash-based lookups only. Files are not uploaded.

**Q: Will fraudsters know I'm scanning their site?**
A: No, the scanning happens after download. They only see normal HTTP requests.

**Q: Can I scan without cloning?**
A: No, but you can use `-d 0` to clone just one page with minimal resources.

**Q: What if I don't have an API key?**
A: The tool works fine without scanning. Get a free key for enhanced security.

**Q: Are scan results admissible as evidence?**
A: Consult legal counsel. VirusTotal is widely recognized, but requirements vary.

## Additional Resources

- VirusTotal Documentation: https://developers.virustotal.com/reference/overview
- VirusTotal GUI: https://www.virustotal.com/gui/home/upload
- API Key Management: https://www.virustotal.com/gui/user/[username]/apikey
