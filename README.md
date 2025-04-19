# README.md
# Red Team Recon Suite

A full-featured, terminal-based reconnaissance toolkit designed for red teamers, bug bounty hunters, and penetration testers. This modular Python project replicates the core functionality of tools like **ReconFTW** with a clean, extensible architecture.

---

## Features

### 🕵️ OSINT Modules
- WHOIS Lookup
- Email Address Enumeration
- Credential Leak Discovery (public pastebin/hibp APIs)
- PDF/DOC/XLS Metadata Search (Google Dorks)
- Exposed API Discovery (Porch Pirate)
- Spoof Check (SPF, DKIM, DMARC)
- LinkedIn Profile Enumeration
- Employee Name + Phone Discovery from Web & PDF

### 🌐 Subdomain Discovery
- Passive Subdomain Enumeration (Subfinder, Assetfinder, Amass, crt.sh)
- DNS Record Collection (A, AAAA, MX, CNAME, TXT, SOA)
- Subdomain Takeover Check
- DNS Takeover Check
- Live Resolution (dnsx)

### 💻 Host Enumeration
- IP Info Lookup (ASN, location, reverse DNS)
- WAF Detection
- TCP Port Scanning (masscan & nmap fallback)
- Service/Version Detection
- Vulnerability Scripts (Nmap Vuln NSEs)
- SSL/TLS Certificate Info (sslscan)

### 🕸 Web Recon
- Web Prober (httpx)
- Screenshot Recon (optional future feature)
- Directory Fuzzing (ffuf)
- Web Template Scanner (nuclei)
- CMS Detection (whatweb)
- JavaScript Analyzer:
  - JS file enumeration
  - API route discovery
  - Secrets in JS (API keys, tokens, JWTs)
  - Debug flags, unsafe eval, and DOM XSS sinks/sources
- Endpoint & Param Discovery (via LinkFinder)
- Discovery of `robots.txt`, `sitemap.xml`
- Active Web Attacks:
  - Open Redirects
  - Host Header Injection
  - CORS Misconfiguration Checks

---

## Project Structure

```
recon-suite/
├── recon.py                         # Main CLI entry point
├── config.yaml                      # Configuration file (API keys, settings)
├── requirements.txt                 # Python module dependencies
├── install_tools_kali.sh            # Installer script for Kali Linux
├── install_tools_macos.sh           # Installer script for macOS (brew-based)
├── README.md                        # Project documentation
├── reports/                         # Output directory for all scan results
│   └── <domain>_*.txt               # Individual recon report files
├── logs/                            # Log files from each scan
│   └── recon_<timestamp>.log        # Timestamped logs per session
├── tools/
│   └── LinkFinder/                  # Cloned LinkFinder repo for JS endpoint analysis
├── utils/
│   ├── logger.py                    # Timestamped logging utility
│   └── helpers.py                   # Common helper functions (file I/O, validation, etc.)
├── modules/
│   ├── osint/
│   │   ├── __init__.py
│   │   ├── whois_lookup.py          # WHOIS info collection
│   │   ├── emailfinder.py           # Email scraping + regex
│   │   ├── leaks.py                 # Pastebin/HIBP-style leak check
│   │   ├── metadata_finder.py       # Google dorking for file metadata
│   │   ├── porch_pirate.py          # API/Swagger leak discovery
│   │   ├── spoofcheck.py            # SPF, DKIM, DMARC validation
│   │   ├── people_contacts.py       # LinkedIn, staff, phone + name scraper
│   ├── subdomains/
│   │   ├── __init__.py
│   │   ├── passive_enum.py          # Amass, crt.sh, subfinder, assetfinder
│   │   ├── dns_records.py           # A, MX, CNAME, TXT, SOA records
│   │   ├── takeover_scan.py         # Subdomain takeover checker
│   │   ├── dns_takeover.py          # DNS unresolvable CNAMEs
│   │   ├── dns_resolver.py          # DNS live validation using dnsx
│   ├── hosts/
│   │   ├── __init__.py
│   │   ├── ip_info.py               # IP geolocation, ASN, RDNS
│   │   ├── waf_check.py             # WAF detection (e.g., AWS WAF)
│   │   ├── port_scanner.py          # masscan/Nmap fallback scan
│   │   ├── vuln_scan.py             # Nmap vuln scripts
│   │   ├── ssl_checker.py           # SSL/TLS scan using sslscan
│   ├── webs/
│   │   ├── __init__.py
│   │   ├── web_probe.py             # HTTPX-based live site discovery
│   │   ├── template_scanner.py      # Nuclei scan against live hosts
│   │   ├── cms_detector.py          # CMS & tech fingerprinting
│   │   ├── js_analyzer.py           # Advanced JS endpoint + secret scanner
│   │   ├── discovery_paths.py       # Fuzzing, robots.txt, sitemap.xml
│   │   ├── fuzzer.py                # FFUF-based content fuzzing
│   │   ├── active_web_attacks.py    # CORS, redirect, header injection testing

```

---

## Setup (Kali Linux / WSL / Ubuntu)

### Clone the repo
```bash
git clone https://github.com/adriank31/recon-suite.git
cd recon-suite
```

### Create Python environment & install dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Dependencies
Ensure these are installed (auto-install script available):
- `whois`, `curl`, `nmap`, `masscan`
- `subfinder`, `assetfinder`, `amass`, `dnsx`
- `ffuf`, `httpx`, `nuclei`, `whatweb`
- `sslscan`, `LinkFinder` (cloned into `tools/LinkFinder/`)

```bash
# For Kali
./install_tools_kali.sh

# For macOS (with brew)
./install_tools_macos.sh
```

### Install Go-based tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```
---

## Usage Examples

### Full Recon
```bash
python3 recon.py -d example.com --all
```

### Individual Modules
```bash
python3 recon.py -d example.com --osint      # Run OSINT module only
python3 recon.py -d example.com --subdomains # Subdomain enumeration
python3 recon.py -d example.com --webs       # Web recon modules
python3 recon.py -i 192.168.1.1 --hosts       # IP-based recon
```

---

## Output Locations

- `reports/` → Recon results by module (TXT)
- `logs/` → Timestamped execution logs

---


## install_tools_kali.sh
- Remember to run command `chmod +x install_tools_kali.sh`
- And then `./install_tools_kali.sh`
- Works for Kali Linux, Parrot Security OS, Ubuntu (Desktop/Server), Debian (11/12+), Linux Mint, Pop!_OS, Zorin OS Elementary OS

---

## install_tools_macos.sh
- Remember to run command `chmod +x install_tools_macos.sh`
- And then `./install_tools_macos.sh`
- Works for macOS (any modern version), but you need to have Homebrew installed and configured


## Disclaimer
> ⚠️ Use this toolkit only against assets you own or have explicit permission to test. Unauthorized use is illegal and unethical.

---

## Credits & Inspirations
- [ReconFTW](https://github.com/six2dez/reconftw)
- ProjectDiscovery ecosystem (Subfinder, Nuclei, HTTPx)
- Tomnomnom’s Assetfinder & tools

---

## License
MIT License — free to use, modify, and contribute.
