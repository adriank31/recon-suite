# modules/webs/discovery_paths.py

import requests
import os
import subprocess
from urllib.parse import urljoin, urlparse
from utils.logger import log
from utils.helpers import ensure_dir


def fetch_robots(domain):
    log(f"[ROBOTS] Fetching robots.txt for: {domain}")
    try:
        url = f"https://{domain}/robots.txt"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            lines = res.text.splitlines()
            paths = [line.split(":")[1].strip() for line in lines if line.lower().startswith("disallow")]
            return [urljoin(url, p) for p in paths if p]
        else:
            log(f"[ROBOTS] No robots.txt found or access denied.", level="WARN")
    except Exception as e:
        log(f"[ROBOTS] Error fetching robots.txt: {e}", level="ERROR")
    return []


def fetch_sitemap(domain):
    log(f"[SITEMAP] Attempting to fetch sitemap.xml for: {domain}")
    links = []
    try:
        url = f"https://{domain}/sitemap.xml"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            from xml.etree import ElementTree as ET
            root = ET.fromstring(res.content)
            for elem in root.iter():
                if 'loc' in elem.tag:
                    links.append(elem.text.strip())
            return links
        else:
            log(f"[SITEMAP] sitemap.xml not found (HTTP {res.status_code}).", level="WARN")
    except Exception as e:
        log(f"[SITEMAP] Error parsing sitemap.xml: {e}", level="ERROR")
    return []


def run_ffuf(domain):
    log(f"[FFUF] Running FFUF for content discovery on: {domain}")
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    output_file = f"reports/{domain}_ffuf.txt"

    if not os.path.exists(wordlist):
        log("[FFUF] Wordlist not found. Install or specify a valid path.", level="ERROR")
        return

    url = f"https://{domain}/FUZZ"
    try:
        result = subprocess.run([
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403",
            "-of", "csv",
            "-o", output_file,
            "-t", "40"
        ], capture_output=True, text=True, timeout=180)

        if result.returncode == 0:
            log(f"[FFUF] FFUF results saved to {output_file}")
        else:
            log(f"[FFUF] FFUF failed or returned no results: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[FFUF] Error running ffuf: {e}", level="ERROR")


def run(domain):
    output_file = f"reports/{domain}_discovery_paths.txt"
    ensure_dir("reports")
    collected = []

    # robots.txt
    robots = fetch_robots(domain)
    collected.extend(robots)

    # sitemap.xml
    sitemap = fetch_sitemap(domain)
    collected.extend(sitemap)

    try:
        with open(output_file, "w") as f:
            for item in sorted(set(collected)):
                f.write(item + "\n")
        log(f"[DISCOVERY] Saved robots.txt & sitemap links to {output_file}")
    except Exception as e:
        log(f"[DISCOVERY] Error saving discovery paths: {e}", level="ERROR")

    # FFUF Fuzzing
    run_ffuf(domain)
