#!/bin/bash

# install_tools_kali.sh
# Installs all required tools for recon-suite on Kali Linux

set -e

echo "[+] Updating system..."
sudo apt update && sudo apt upgrade -y

# Core dependencies
sudo apt install -y whois curl nmap masscan dnsutils git python3-pip python3-venv make unzip wget gnupg lsb-release ca-certificates

# Go & recon tools
if ! command -v go &> /dev/null; then
    echo "[+] Installing Go..."
    sudo apt install -y golang-go
fi

export PATH=$PATH:$(go env GOPATH)/bin

echo "[+] Installing subdomain tools..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

go install github.com/tomnomnom/assetfinder@latest
sudo cp ~/go/bin/assetfinder /usr/local/bin/

go install github.com/owasp-amass/amass/v4/...@master
sudo cp ~/go/bin/amass /usr/local/bin/


echo "[+] Installing dnsx..."
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo cp ~/go/bin/dnsx /usr/local/bin/

echo "[+] Installing httpx..."
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/local/bin/


echo "[+] Installing nuclei..."
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/


echo "[+] Installing ffuf..."
go install github.com/ffuf/ffuf@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/


echo "[+] Installing whatweb..."
sudo apt install -y whatweb


echo "[+] Installing sslscan..."
sudo apt install -y sslscan

# Python dependencies
echo "[+] Installing Python dependencies..."
pip install -r requirements.txt

# LinkFinder setup
if [ ! -d "tools/LinkFinder" ]; then
  echo "[+] Cloning LinkFinder..."
  mkdir -p tools && cd tools
  git clone https://github.com/GerbenJavado/LinkFinder.git
  cd LinkFinder
  pip install -r requirements.txt
  cd ../../
fi


echo "[✓] All tools installed. recon-suite is ready to use."
echo "[!] Activate your virtual environment before scanning: source venv/bin/activate"
