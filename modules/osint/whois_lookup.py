# modules/osint/whois_lookup.py

import subprocess
from utils.logger import log

def run(domain):
    log(f"[WHOIS] Performing WHOIS lookup for: {domain}")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            output_path = f"reports/{domain}_whois.txt"
            with open(output_path, "w") as f:
                f.write(result.stdout)
            log(f"[WHOIS] Saved WHOIS data to {output_path}")
        else:
            log(f"[WHOIS] Error running whois: {result.stderr}")
    except Exception as e:
        log(f"[WHOIS] Exception occurred: {e}")
