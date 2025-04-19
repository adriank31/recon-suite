# modules/webs/js_analyzer.py

import requests
import re
import os
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from utils.logger import log

def extract_js_urls(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    script_urls = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            full_url = urljoin(base_url, src)
            script_urls.append(full_url)
    return script_urls

def extract_secrets(js_text):
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Heroku API Key": r"[hH]eroku[a-zA-Z0-9]{32,}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}"
    }
    secrets = []
    for label, regex in patterns.items():
        matches = re.findall(regex, js_text)
        for match in matches:
            secrets.append((label, match))
    return secrets

def run(domain):
    log(f"[JS ANALYZER] Analyzing JavaScript files for secrets on: {domain}")

    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_js_analysis.txt"

    if not os.path.exists(input_file):
        log(f"[JS ANALYZER] Web probe results missing: {input_file}")
        return

    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

        all_js_links = []
        found_secrets = []

        for url in urls:
            try:
                log(f"[JS ANALYZER] Fetching HTML from {url}")
                res = requests.get(url, timeout=10)
                if res.status_code != 200:
                    continue
                js_links = extract_js_urls(res.text, url)
                all_js_links.extend(js_links)

                for js_url in js_links:
                    log(f"[JS ANALYZER] Downloading {js_url}")
                    js_res = requests.get(js_url, timeout=10)
                    if js_res.status_code != 200:
                        continue
                    secrets = extract_secrets(js_res.text)
                    if secrets:
                        for label, secret in secrets:
                            found_secrets.append((js_url, label, secret))

            except Exception as e:
                log(f"[JS ANALYZER] Error analyzing {url}: {e}")

        with open(output_file, "w") as f:
            f.write("Discovered JavaScript Links:\n")
            for js in sorted(set(all_js_links)):
                f.write(js + "\n")

            f.write("\nDiscovered Secrets in JavaScript Files:\n")
            for js_url, label, secret in found_secrets:
                f.write(f"{label} in {js_url}: {secret}\n")

        log(f"[JS ANALYZER] JavaScript analysis complete. Results saved to {output_file}")

    except Exception as e:
        log(f"[JS ANALYZER] General exception: {e}")
