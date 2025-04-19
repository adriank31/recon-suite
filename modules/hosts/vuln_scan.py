# modules/hosts/vuln_scan.py

import subprocess
import os
from utils.logger import log


def run(target):
    log(f"[VULN SCAN] Launching vulnerability checks for: {target}")

    input_ports_file = f"reports/{target}_ports.txt"
    output_file = f"reports/{target}_vuln_scan.txt"

    ports = []

    if os.path.exists(input_ports_file):
        with open(input_ports_file, "r") as f:
            for line in f:
                if "open tcp port" in line:
                    port = line.split("port")[-1].strip()
                    ports.append(port)
    else:
        log(f"[VULN SCAN] Port scan file not found, using default ports")
        ports = ["21", "22", "80", "443", "445", "3306"]

    port_arg = ",".join(ports)

    try:
        log(f"[VULN SCAN] Running Nmap vuln scripts on ports: {port_arg}")
        cmd = [
            "nmap",
            "-sV",
            "-sC",
            "--script", "vuln",
            "-p", port_arg,
            target
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        with open(output_file, "w") as f:
            f.write(result.stdout)

        log(f"[VULN SCAN] Vulnerability scan complete. Results saved to {output_file}")

    except subprocess.TimeoutExpired:
        log(f"[VULN SCAN] Scan timed out after 5 minutes.")
    except Exception as e:
        log(f"[VULN SCAN] Error during vulnerability scan: {e}")
