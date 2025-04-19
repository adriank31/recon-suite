# modules/subdomains/passive_enum.py

import subprocess
import requests
import json
import os
from utils.logger import log
from utils.helpers import ensure_dir

CRT_SH_URL = "https://crt.sh/?q={}&output=json"


def query_crtsh(domain):
    log(f"[CRT.SH] Querying certificate transparency logs for: {domain}")
    found = set()
    try:
        res = requests.get(CRT_SH_URL.format(domain), timeout=15)
        if res.status_code == 200:
            json_data = res.json()
            for entry in json_data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    if sub.endswith(domain):
                        found.add(sub.strip().lower())
        else:
            log(f"[CRT.SH] Unexpected HTTP status code: {res.status_code}", level="WARN")
    except Exception as e:
        log(f"[CRT.SH] Exception during crt.sh query: {e}", level="ERROR")
    return found


def run(domain):
    log(f"[SUBDOMAINS] Running passive subdomain enumeration for: {domain}")
    output_file = f"reports/{domain}_subdomains.txt"
    all_subdomains = set()

    ensure_dir("reports")

    # Subfinder
    log("[SUBDOMAINS] Using subfinder...")
    try:
        result = subprocess.run([
            "subfinder", "-d", domain, "-silent"
        ], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                all_subdomains.add(line.strip().lower())
        else:
            log(f"[SUBDOMAINS] subfinder error: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[SUBDOMAINS] subfinder exception: {e}", level="ERROR")

    # Assetfinder
    log("[SUBDOMAINS] Using assetfinder...")
    try:
        result = subprocess.run([
            "assetfinder", "--subs-only", domain
        ], capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.endswith(domain):
                    all_subdomains.add(line.strip().lower())
        else:
            log(f"[SUBDOMAINS] assetfinder error: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[SUBDOMAINS] assetfinder exception: {e}", level="ERROR")

    # crt.sh
    crt_results = query_crtsh(domain)
    all_subdomains.update(crt_results)

    # Amass
    log("[SUBDOMAINS] Using Amass (passive mode)...")
    try:
        result = subprocess.run([
            "amass", "enum", "-passive", "-d", domain
        ], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                all_subdomains.add(line.strip().lower())
        else:
            log(f"[SUBDOMAINS] amass error: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[SUBDOMAINS] amass exception: {e}", level="ERROR")

    # Save output
    try:
        with open(output_file, "w") as f:
            for sub in sorted(all_subdomains):
                f.write(sub + "\n")
        log(f"[SUBDOMAINS] Found {len(all_subdomains)} subdomains. Saved to {output_file}")
    except Exception as e:
        log(f"[SUBDOMAINS] Failed to save subdomains: {e}", level="ERROR")
