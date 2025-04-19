# modules/subdomains/dns_resolver.py

import subprocess
import os
from utils.logger import log
from utils.helpers import ensure_dir


def run(domain):
    input_file = f"reports/{domain}_subdomains.txt"
    output_file = f"reports/{domain}_resolved.txt"
    ensure_dir("reports")

    if not os.path.exists(input_file):
        log(f"[DNSX] Subdomain list not found: {input_file}", level="ERROR")
        return

    try:
        result = subprocess.run([
            "dnsx",
            "-l", input_file,
            "-silent",
            "-a",
            "-resp",
            "-json",
            "-o", output_file
        ], capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            log(f"[DNSX] Active subdomains resolved and saved to {output_file}")
        else:
            log(f"[DNSX] Error resolving subdomains: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[DNSX] Exception during DNS resolution: {e}", level="ERROR")
