#!/bin/bash

# install_tools_macos.sh
# Installs all required tools for recon-suite on macOS with Homebrew

# Check for Homebrew
if ! command -v brew &> /dev/null; then
  echo "[!] Homebrew not found. Please install it first from https://brew.sh"
  exit 1
fi

echo "[+] Updating Homebrew..."
brew update

# Install core tools
brew install whois curl nmap masscan git python3

# Install Go if not found
if ! command -v go &> /dev/null; then
  echo "[+] Installing Go..."
  brew install go
fi

export PATH=$PATH:$(go env GOPATH)/bin

# Install recon tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

go install github.com/tomnomnom/assetfinder@latest
sudo cp ~/go/bin/assetfinder /usr/local/bin/

go install github.com/owasp-amass/amass/v4/...@master
sudo cp ~/go/bin/amass /usr/local/bin/

go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
sudo cp ~/go/bin/dnsx /usr/local/bin/

go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/local/bin/

go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/

go install github.com/ffuf/ffuf@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/

# Install whatweb equivalent
brew install whatweb

# Install sslscan
brew install sslscan

# Clone and setup LinkFinder
mkdir -p tools && cd tools
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
cd ../../


echo "[+] All recon-suite tools installed successfully on macOS."
echo "[+] Make sure your virtual environment is activated before running scans."
