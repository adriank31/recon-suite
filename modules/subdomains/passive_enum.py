# modules/subdomains/passive_enum.py

import subprocess
from utils.logger import log
import os

def run(domain):
    log(f"[SUBDOMAINS] Running passive subdomain enumeration for: {domain}")

    tools = [
        ("subfinder", ["subfinder", "-d", domain, "-silent"]),
        ("assetfinder", ["assetfinder", "--subs-only", domain])
    ]

    output_path = f"reports/{domain}_subdomains.txt"
    found = set()

    for name, cmd in tools:
        try:
            log(f"[SUBDOMAINS] Using {name}...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if domain in line:
                        found.add(line.strip())
            else:
                log(f"[SUBDOMAINS] {name} failed: {result.stderr}")
        except Exception as e:
            log(f"[SUBDOMAINS] {name} error: {e}")

    with open(output_path, "w") as f:
        for sub in sorted(found):
            f.write(sub + "\n")

    log(f"[SUBDOMAINS] Found {len(found)} subdomains. Saved to {output_path}")
