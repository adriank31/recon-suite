# README.md

# 🛡️ Red Team Recon Suite

A full-featured, terminal-based reconnaissance toolkit designed for red teamers, bug bounty hunters, and penetration testers. This modular Python project replicates the core functionality of tools like **ReconFTW** with a clean, extensible architecture.

---

## 🔧 Features

### OSINT
- WHOIS Information
- Email + Leak Search (Wayback + Leak-Lookup)
- Metadata Dorks (PDF/DOC/XLS)
- Swagger/OpenAPI Exposure
- Spoofable Domain Checks (SPF, DKIM, DMARC)

### Subdomain Enumeration
- Passive Subdomain Discovery (Subfinder + Assetfinder)
- DNS Record Collection + Zone Transfer
- Subdomain Takeover Scanning
- Dangling CNAME / DNS Takeover Detection

### Host Recon
- IP Ownership and Geolocation (IPInfo)
- WAF Detection
- Fast Port Scanning (Masscan/Nmap)
- Vulnerability Scanning (Nmap Vuln Scripts)

### Web Recon
- Live HTTP Probing (httpx)
- Web Template Scanning (Nuclei)
- CMS Detection (WhatWeb)
- JavaScript File + Secrets Analyzer
- Web Directory Fuzzing (Gobuster)

---

## 🗂 Project Structure

```
recon-suite/
├── recon.py                 # 🔹 Main CLI launcher
├── config.yaml              # ⚙️  Global config for timeouts, wordlists, API keys
├── requirements.txt         # 📦 Python dependencies
├── README.md                # 📘 Project documentation
├── modules/                 # 🧩 All recon modules (grouped by category)
│   ├── __init__.py
│   ├── osint/
│   │   ├── whois_lookup.py
│   │   ├── emailfinder.py
│   │   ├── leaks.py
│   │   ├── metadata_finder.py
│   │   ├── porch_pirate.py
│   │   └── spoofcheck.py
│   ├── subdomains/
│   │   ├── passive_enum.py
│   │   ├── dns_records.py
│   │   ├── takeover_scan.py
│   │   └── dns_takeover.py
│   ├── hosts/
│   │   ├── ip_info.py
│   │   ├── waf_check.py
│   │   ├── port_scanner.py
│   │   └── vuln_scan.py
│   └── webs/
│       ├── web_probe.py
│       ├── template_scanner.py
│       ├── cms_detector.py
│       ├── js_analyzer.py
│       └── fuzzer.py
├── utils/                   # 🛠 Utility support
│   ├── logger.py
│   ├── runner.py
│   └── helpers.py
├── reports/                 # 📄 All generated recon results (auto-created)
│   ├── example.com_whois.txt
│   ├── example.com_subdomains.txt
│
├── logs/                    # 📋 Timestamped logs for every scan (auto-created)
│   ├── recon_20250417_163012.log
│
```

---

## 🚀 Usage Examples

```bash
# Full recon on domain
python3 recon.py -d example.com --all

# Run only OSINT
python3 recon.py -d example.com --osint

# IP-specific scan
python3 recon.py -i 192.168.1.1 --hosts
```

---

## 📦 Requirements

Install required tools and dependencies:
```bash
sudo apt install nmap masscan gobuster whois curl dnsutils
pip install -r requirements.txt
```

Ensure the following CLI tools are installed and in your PATH:
- subfinder
- assetfinder
- httpx
- nuclei
- whatweb
- gobuster
- masscan
- nmap

---

## 📘 Credits & Acknowledgements
- Inspired by [ReconFTW](https://github.com/six2dez/reconftw)
- Uses tools by ProjectDiscovery, OWASP Amass, and the open-source security community

---

## ⚠️ Legal Notice
Use this tool only on targets you own or are explicitly authorized to test. Unauthorized scanning is illegal and unethical.

---

## 🧠 Author
Built for red team training, research, and offensive security practice.
