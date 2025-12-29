#!/usr/bin/env python3
"""
Website Cloner - For Documentation and Archival Purposes
Creates local copies of websites for evidence preservation and record-keeping.
"""

import os
import sys
import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from pathlib import Path
import mimetypes
from datetime import datetime
import json
import hashlib
import time

# Set UTF-8 encoding for Windows console
if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')


def load_env_file(env_path='.env'):
    """Load environment variables from .env file if it exists"""
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    # Split on first = only
                    if '=' in line:
                        key, value = line.split('=', 1)
                        # Remove quotes if present
                        value = value.strip().strip('"').strip("'")
                        os.environ[key.strip()] = value


class VirusScanner:
    """Integrates with VirusTotal API for malware scanning"""

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.enabled = api_key is not None
        self.base_url = "https://www.virustotal.com/api/v3"
        self.scan_results = []
        self.total_scanned = 0
        self.threats_found = 0

    def scan_file(self, file_path, file_hash):
        """Scan a file using VirusTotal API"""
        if not self.enabled:
            return None

        try:
            # First, check if the hash is already known to VirusTotal
            headers = {
                "x-apikey": self.api_key
            }

            # Check file hash
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total_engines = sum(stats.values())

                result = {
                    "file": str(file_path),
                    "sha256": file_hash,
                    "scan_date": datetime.now().isoformat(),
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "total_engines": total_engines,
                    "is_threat": malicious > 0 or suspicious > 0,
                    "scan_type": "hash_lookup"
                }

                self.total_scanned += 1
                if result["is_threat"]:
                    self.threats_found += 1
                    print(f"    ⚠ THREAT DETECTED: {malicious} engines flagged as malicious, {suspicious} as suspicious")
                else:
                    print(f"    ✓ Clean: 0/{total_engines} engines detected threats")

                self.scan_results.append(result)
                return result

            elif response.status_code == 404:
                # File not in database, would need to upload (requires different API tier)
                result = {
                    "file": str(file_path),
                    "sha256": file_hash,
                    "scan_date": datetime.now().isoformat(),
                    "status": "unknown",
                    "message": "File not in VirusTotal database",
                    "scan_type": "hash_lookup"
                }
                self.total_scanned += 1
                self.scan_results.append(result)
                print(f"    ℹ Not in VirusTotal database (file may be new/unique)")
                return result

            else:
                print(f"    ✗ Scan failed: HTTP {response.status_code}")
                return None

        except Exception as e:
            print(f"    ✗ Scan error: {str(e)}")
            return None

    def get_summary(self):
        """Get scanning summary"""
        return {
            "total_scanned": self.total_scanned,
            "threats_found": self.threats_found,
            "scan_results": self.scan_results
        }


class WebsiteCloner:
    def __init__(self, url, output_dir=None, max_depth=3, same_domain_only=True,
                 virus_scanner=None, scan_downloads=False):
        self.start_url = url
        self.domain = urlparse(url).netloc
        self.visited_urls = set()
        self.failed_urls = set()
        self.max_depth = max_depth
        self.same_domain_only = same_domain_only
        self.virus_scanner = virus_scanner
        self.scan_downloads = scan_downloads

        # Create output directory
        if output_dir is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_domain = self.domain.replace(".", "_").replace(":", "_")
            output_dir = f"clone_{safe_domain}_{timestamp}"

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Metadata tracking
        self.metadata = {
            "start_url": url,
            "clone_date": datetime.now().isoformat(),
            "domain": self.domain,
            "max_depth": max_depth,
            "pages_cloned": [],
            "resources_downloaded": [],
            "failed_downloads": [],
            "virus_scanning_enabled": scan_downloads and virus_scanner is not None
        }

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def get_file_hash(self, content):
        """Generate SHA256 hash of content for integrity verification"""
        return hashlib.sha256(content).hexdigest()

    def url_to_filepath(self, url):
        """Convert URL to a local file path"""
        parsed = urlparse(url)
        path = parsed.path.strip('/')

        if not path:
            path = 'index.html'
        elif not os.path.splitext(path)[1]:
            # If no extension, assume it's a directory
            path = os.path.join(path, 'index.html')

        # Create full path
        full_path = self.output_dir / parsed.netloc / path
        return full_path

    def download_resource(self, url, referer=None):
        """Download a resource (image, CSS, JS, etc.)"""
        if url in self.visited_urls or url in self.failed_urls:
            return None

        try:
            headers = {}
            if referer:
                headers['Referer'] = referer

            response = self.session.get(url, timeout=30, headers=headers)
            response.raise_for_status()

            filepath = self.url_to_filepath(url)
            filepath.parent.mkdir(parents=True, exist_ok=True)

            # Write content
            filepath.write_bytes(response.content)

            # Record metadata
            file_hash = self.get_file_hash(response.content)
            resource_metadata = {
                "url": url,
                "local_path": str(filepath),
                "size_bytes": len(response.content),
                "sha256": file_hash,
                "content_type": response.headers.get('Content-Type', 'unknown')
            }

            # Virus scan if enabled
            if self.scan_downloads and self.virus_scanner:
                print(f"  ✓ Downloaded resource: {url}")
                print(f"    Scanning for threats...")
                scan_result = self.virus_scanner.scan_file(filepath, file_hash)
                if scan_result:
                    resource_metadata["virus_scan"] = scan_result
                # Rate limiting for VirusTotal API (4 requests/minute for free tier)
                time.sleep(15)
            else:
                print(f"  ✓ Downloaded resource: {url}")

            self.metadata["resources_downloaded"].append(resource_metadata)
            self.visited_urls.add(url)
            return filepath

        except Exception as e:
            print(f"  ✗ Failed to download {url}: {str(e)}")
            self.failed_urls.add(url)
            self.metadata["failed_downloads"].append({
                "url": url,
                "error": str(e)
            })
            return None

    def clone_page(self, url, depth=0):
        """Clone a single page and its resources"""
        if depth > self.max_depth:
            return

        if url in self.visited_urls or url in self.failed_urls:
            return

        # Check if same domain only
        if self.same_domain_only and urlparse(url).netloc != self.domain:
            return

        print(f"\n{'  ' * depth}Cloning [{depth}/{self.max_depth}]: {url}")

        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')

            # Only process HTML pages
            if 'text/html' not in content_type:
                self.download_resource(url)
                return

            soup = BeautifulSoup(response.content, 'html.parser')

            # Download resources (images, CSS, JS, etc.)
            resource_tags = {
                'img': 'src',
                'link': 'href',
                'script': 'src',
                'source': 'src',
                'video': 'src',
                'audio': 'src'
            }

            for tag_name, attr in resource_tags.items():
                for tag in soup.find_all(tag_name):
                    if tag.get(attr):
                        resource_url = urljoin(url, tag[attr])
                        self.download_resource(resource_url, referer=url)

            # Save the HTML page
            filepath = self.url_to_filepath(url)
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_bytes(response.content)

            # Record metadata
            file_hash = self.get_file_hash(response.content)
            page_metadata = {
                "url": url,
                "local_path": str(filepath),
                "depth": depth,
                "size_bytes": len(response.content),
                "sha256": file_hash,
                "timestamp": datetime.now().isoformat()
            }

            # Virus scan if enabled
            if self.scan_downloads and self.virus_scanner:
                print(f"  ✓ Saved page: {filepath}")
                print(f"    Scanning for threats...")
                scan_result = self.virus_scanner.scan_file(filepath, file_hash)
                if scan_result:
                    page_metadata["virus_scan"] = scan_result
                # Rate limiting for VirusTotal API
                time.sleep(15)
            else:
                print(f"  ✓ Saved page: {filepath}")

            self.metadata["pages_cloned"].append(page_metadata)
            self.visited_urls.add(url)

            # Find and clone linked pages
            if depth < self.max_depth:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])

                    # Remove fragment
                    next_url = next_url.split('#')[0]

                    # Skip non-http(s) links
                    if not next_url.startswith(('http://', 'https://')):
                        continue

                    if self.same_domain_only and urlparse(next_url).netloc != self.domain:
                        continue

                    self.clone_page(next_url, depth + 1)

        except Exception as e:
            print(f"  ✗ Failed to clone {url}: {str(e)}")
            self.failed_urls.add(url)
            self.metadata["failed_downloads"].append({
                "url": url,
                "error": str(e)
            })

    def save_metadata(self):
        """Save clone metadata to JSON file"""
        metadata_file = self.output_dir / "clone_metadata.json"
        self.metadata["total_pages"] = len(self.metadata["pages_cloned"])
        self.metadata["total_resources"] = len(self.metadata["resources_downloaded"])
        self.metadata["total_failed"] = len(self.metadata["failed_downloads"])

        # Add virus scanning summary if enabled
        if self.scan_downloads and self.virus_scanner:
            self.metadata["virus_scan_summary"] = self.virus_scanner.get_summary()

        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(self.metadata, f, indent=2)

        print(f"\n✓ Metadata saved to: {metadata_file}")

    def create_index(self):
        """Create an index.html file for easy navigation"""
        index_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Website Clone - {self.domain}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background-color: #333;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-box {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #0066cc;
        }}
        .pages-list {{
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .page-item {{
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}
        .page-item:hover {{
            background-color: #f9f9f9;
        }}
        a {{
            color: #0066cc;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Website Clone Archive</h1>
        <p><strong>Original URL:</strong> <a href="{self.start_url}" target="_blank">{self.start_url}</a></p>
        <p><strong>Clone Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Purpose:</strong> Documentation and archival for fraud prevention</p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{len(self.metadata['pages_cloned'])}</div>
            <div>Pages Cloned</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len(self.metadata['resources_downloaded'])}</div>
            <div>Resources Downloaded</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{len(self.failed_urls)}</div>
            <div>Failed Downloads</div>
        </div>
    </div>

    <div class="pages-list">
        <h2>Cloned Pages</h2>
"""

        for page in self.metadata['pages_cloned']:
            relative_path = os.path.relpath(page['local_path'], self.output_dir)
            index_html += f"""        <div class="page-item">
            <a href="{relative_path.replace(os.sep, '/')}">{page['url']}</a>
            <br><small>SHA256: {page['sha256']}</small>
        </div>
"""

        index_html += """    </div>
</body>
</html>"""

        index_file = self.output_dir / "index.html"
        index_file.write_text(index_html, encoding='utf-8')
        print(f"✓ Index page created: {index_file}")

    def run(self):
        """Execute the cloning process"""
        print(f"\n{'='*60}")
        print(f"Website Cloner - Documentation & Archival Tool")
        print(f"{'='*60}")
        print(f"Target: {self.start_url}")
        print(f"Output: {self.output_dir}")
        print(f"Max Depth: {self.max_depth}")
        print(f"Same Domain Only: {self.same_domain_only}")
        print(f"Virus Scanning: {'Enabled' if self.scan_downloads else 'Disabled'}")
        print(f"{'='*60}\n")

        self.clone_page(self.start_url, depth=0)
        self.save_metadata()
        self.create_index()

        print(f"\n{'='*60}")
        print(f"Clone Complete!")
        print(f"{'='*60}")
        print(f"Pages cloned: {len(self.metadata['pages_cloned'])}")
        print(f"Resources downloaded: {len(self.metadata['resources_downloaded'])}")
        print(f"Failed downloads: {len(self.failed_urls)}")

        if self.scan_downloads and self.virus_scanner:
            summary = self.virus_scanner.get_summary()
            print(f"\n{'='*60}")
            print(f"Virus Scan Summary")
            print(f"{'='*60}")
            print(f"Files scanned: {summary['total_scanned']}")
            print(f"Threats detected: {summary['threats_found']}")
            if summary['threats_found'] > 0:
                print(f"\n⚠ WARNING: Threats were detected in downloaded files!")
                print(f"   Review the metadata file for details.")
            print(f"{'='*60}")

        print(f"\nOutput directory: {self.output_dir.absolute()}")
        print(f"Open {self.output_dir / 'index.html'} to view the archive")
        print(f"{'='*60}\n")


def main():
    # Load .env file if it exists
    load_env_file()

    parser = argparse.ArgumentParser(
        description='Clone websites for documentation and archival purposes with optional virus scanning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python site_cloner.py https://example.com
  python site_cloner.py https://example.com -o my_archive -d 2
  python site_cloner.py https://example.com --all-domains -d 1
  python site_cloner.py https://suspicious-site.com --scan --vt-api-key YOUR_API_KEY

Virus Scanning:
  To enable virus scanning, you need a VirusTotal API key (free tier available).
  Get your API key at: https://www.virustotal.com/gui/join-us

  Three ways to provide your API key:
  1. Create a .env file (copy from .env.example)
  2. Set environment variable: VIRUSTOTAL_API_KEY=your_key
  3. Pass directly: --vt-api-key your_key

Legal Notice:
  This tool is intended for legitimate documentation and archival purposes.
  Always ensure you have permission to archive content and respect robots.txt.
  Use responsibly and in compliance with applicable laws and terms of service.
        """
    )

    parser.add_argument('url', help='URL of the website to clone')
    parser.add_argument('-o', '--output', help='Output directory (default: auto-generated)')
    parser.add_argument('-d', '--depth', type=int, default=3,
                       help='Maximum crawl depth (default: 3)')
    parser.add_argument('--all-domains', action='store_true',
                       help='Allow cloning resources from other domains')
    parser.add_argument('--scan', action='store_true',
                       help='Enable virus scanning of downloaded files')
    parser.add_argument('--vt-api-key', help='VirusTotal API key (or set VIRUSTOTAL_API_KEY env var)')

    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)

    # Setup virus scanner if requested
    virus_scanner = None
    if args.scan:
        api_key = args.vt_api_key or os.environ.get('VIRUSTOTAL_API_KEY')
        if not api_key:
            print("Error: Virus scanning requires a VirusTotal API key.")
            print("Get a free API key at: https://www.virustotal.com/gui/join-us")
            print("\nProvide the key via:")
            print("  --vt-api-key YOUR_KEY")
            print("  or set environment variable VIRUSTOTAL_API_KEY")
            sys.exit(1)

        virus_scanner = VirusScanner(api_key=api_key)
        print("\n✓ Virus scanning enabled via VirusTotal API")
        print("  Note: Free tier has rate limits (4 requests/minute)")
        print("  Scanning will add significant time to the clone process\n")

    try:
        cloner = WebsiteCloner(
            url=args.url,
            output_dir=args.output,
            max_depth=args.depth,
            same_domain_only=not args.all_domains,
            virus_scanner=virus_scanner,
            scan_downloads=args.scan
        )
        cloner.run()
    except KeyboardInterrupt:
        print("\n\nCloning interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
