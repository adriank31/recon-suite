# modules/hosts/ssl_checker.py

import subprocess
import os
from utils.logger import log
from utils.helpers import ensure_dir

def run(domain):
    output_file = f"reports/{domain}_ssl_info.txt"
    ensure_dir("reports")

    log(f"[SSL/TLS] Running SSL scan for: {domain}")
    try:
        result = subprocess.run([
            "sslscan",
            domain
        ], capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            with open(output_file, "w") as f:
                f.write(result.stdout)
            log(f"[SSL/TLS] SSL scan complete. Results saved to {output_file}")
        else:
            log(f"[SSL/TLS] sslscan error: {result.stderr}", level="WARN")
    except Exception as e:
        log(f"[SSL/TLS] Exception while scanning: {e}", level="ERROR")
