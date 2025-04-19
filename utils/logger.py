# utils/logger.py

import datetime
import os
import sys

LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

log_file = os.path.join(LOG_DIR, f"recon_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")


def log(msg, level="INFO"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    full_msg = f"[{timestamp}] [{level}] {msg}"

    # Print to terminal
    if level == "ERROR":
        print(f"\033[91m{full_msg}\033[0m")  # Red text for errors
    elif level == "WARN":
        print(f"\033[93m{full_msg}\033[0m")  # Yellow text for warnings
    else:
        print(full_msg)

    # Append to log file
    try:
        with open(log_file, "a") as f:
            f.write(full_msg + "\n")
    except Exception as e:
        print(f"[LOGGER] Failed to write to log file: {e}", file=sys.stderr)


def log_banner():
    banner = """
    ======================================
         RED TEAM RECON SUITE LAUNCHED
    ======================================
    """
    print(banner)
    with open(log_file, "a") as f:
        f.write(banner + "\n")


def log_section(title):
    line = f"\n=== {title.upper()} ==="
    print(line)
    with open(log_file, "a") as f:
        f.write(line + "\n")


def log_error(msg):
    log(msg, level="ERROR")


def log_warn(msg):
    log(msg, level="WARN")
