# modules/hosts/port_scanner.py

import subprocess
from utils.logger import log
import os

def run(target):
    log(f"[PORT SCANNER] Running full TCP port scan for: {target}")

    output_file = f"reports/{target}_ports.txt"
    ports_found = []

    try:
        # Use masscan for fast scanning if installed
        log("[PORT SCANNER] Starting fast scan with masscan...")
        masscan_cmd = [
            "masscan", target,
            "-p1-65535",
            "--rate", "10000",
            "--wait", "0",
            "--output-format", "list",
            "--output-filename", output_file
        ]

        result = subprocess.run(masscan_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log("[PORT SCANNER] Masscan completed.")
        else:
            log(f"[PORT SCANNER] Masscan error: {result.stderr}")

        # Parse ports from file
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                for line in f:
                    if "open tcp port" in line:
                        port = line.split("port")[-1].strip()
                        ports_found.append(port)

        # Fallback to nmap if masscan fails or no ports found
        if not ports_found:
            log("[PORT SCANNER] Falling back to Nmap scan...")
            nmap_output = subprocess.run([
                "nmap", "-p-", "-T4", "-Pn", target
            ], capture_output=True, text=True)

            with open(output_file, "w") as f:
                f.write(nmap_output.stdout)

            log("[PORT SCANNER] Nmap results saved.")

    except Exception as e:
        log(f"[PORT SCANNER] Exception occurred: {e}")

    log(f"[PORT SCANNER] Port scan complete. Results saved to {output_file}")
