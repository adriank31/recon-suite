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
├── recon.py                # CLI launcher
├── config.yaml             # Settings
├── modules/                # Recon modules (osint, subdomains, hosts, webs)
├── utils/                  # Logging, helpers, subprocess runner
├── reports/                # Recon results (auto-generated)
└── logs/                   # Execution logs
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
