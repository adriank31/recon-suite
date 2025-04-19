# modules/webs/cms_detector.py

import subprocess
import os
from utils.logger import log

def run(domain):
    log(f"[CMS DETECTOR] Scanning for CMS platforms on: {domain}")

    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_cms_detected.txt"
    detected = []

    if not os.path.exists(input_file):
        log(f"[CMS DETECTOR] Web probe results missing: {input_file}")
        return

    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]

        for url in urls:
            try:
                log(f"[CMS DETECTOR] Scanning {url}...")
                result = subprocess.run(["whatweb", url], capture_output=True, text=True, timeout=20)

                if result.returncode == 0 and result.stdout:
                    detected.append(result.stdout.strip())
                else:
                    log(f"[CMS DETECTOR] No output for {url}")
            except Exception as e:
                log(f"[CMS DETECTOR] Error scanning {url}: {e}")

        with open(output_file, "w") as f:
            for line in detected:
                f.write(line + "\n")

        log(f"[CMS DETECTOR] CMS detection complete. Results saved to {output_file}")

    except Exception as e:
        log(f"[CMS DETECTOR] General error: {e}")
