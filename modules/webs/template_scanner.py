# modules/webs/template_scanner.py

import subprocess
import os
from utils.logger import log

def run(domain):
    log(f"[TEMPLATE SCANNER] Running Nuclei template scanner on: {domain}")

    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_nuclei_scan.txt"

    if not os.path.exists(input_file):
        log(f"[TEMPLATE SCANNER] Web probe results missing: {input_file}")
        return

    try:
        cmd = [
            "nuclei",
            "-l", input_file,
            "-severity", "low,medium,high,critical",
            "-silent",
            "-o", output_file
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode == 0:
            log(f"[TEMPLATE SCANNER] Nuclei scan complete. Results saved to {output_file}")
        else:
            log(f"[TEMPLATE SCANNER] Nuclei error: {result.stderr}")

    except subprocess.TimeoutExpired:
        log("[TEMPLATE SCANNER] Nuclei scan timed out.")
    except Exception as e:
        log(f"[TEMPLATE SCANNER] Error occurred during Nuclei scan: {e}")
