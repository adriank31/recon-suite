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

## ⚙️ Setup (Kali Linux / WSL / Ubuntu)

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/recon-suite.git
cd recon-suite
```

### 2. Create Python environment & install dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Install required tools
```bash
sudo apt install nmap masscan gobuster whatweb whois curl dnsutils golang-go
```

### 4. Install Go-based tools
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

---

## 🚀 Usage Examples

### 🔁 Full Recon
```bash
python3 recon.py -d example.com --all
```

### 🔍 Individual Modules
```bash
python3 recon.py -d example.com --osint      # Run OSINT module only
python3 recon.py -d example.com --subdomains # Subdomain enumeration
python3 recon.py -d example.com --webs       # Web recon modules
python3 recon.py -i 192.168.1.1 --hosts       # IP-based recon
```

---

## 📦 Output Locations

- `reports/` → Recon results by module (TXT)
- `logs/` → Timestamped execution logs

---

## 🔐 Disclaimer
> ⚠️ Use this toolkit only against assets you own or have explicit permission to test. Unauthorized use is illegal and unethical.

---

## 🧠 Credits & Inspirations
- [ReconFTW](https://github.com/six2dez/reconftw)
- ProjectDiscovery ecosystem (Subfinder, Nuclei, HTTPx)
- Tomnomnom’s Assetfinder & tools

---

## 📌 License
MIT License — free to use, modify, and contribute.
