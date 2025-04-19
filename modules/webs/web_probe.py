# modules/webs/web_probe.py

import subprocess
import os
from utils.logger import log

def run(domain):
    log(f"[WEB PROBE] Probing HTTP/S services for: {domain}")

    subdomains_file = f"reports/{domain}_subdomains.txt"
    output_file = f"reports/{domain}_web_probe.txt"
    live_hosts = set()

    if not os.path.exists(subdomains_file):
        log(f"[WEB PROBE] Subdomain list not found: {subdomains_file}")
        return

    try:
        # Run httpx against discovered subdomains
        cmd = ["httpx", "-l", subdomains_file, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("http"):
                    live_hosts.add(line.strip())

            with open(output_file, "w") as f:
                for host in sorted(live_hosts):
                    f.write(host + "\n")

            log(f"[WEB PROBE] Found {len(live_hosts)} live web hosts. Results saved to {output_file}")
        else:
            log(f"[WEB PROBE] httpx error: {result.stderr}")

    except Exception as e:
        log(f"[WEB PROBE] Exception occurred: {e}")
