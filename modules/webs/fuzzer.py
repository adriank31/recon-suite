# modules/webs/fuzzer.py

import subprocess
import os
from utils.logger import log

def run(domain):
    log(f"[FUZZER] Starting content discovery fuzzing for: {domain}")

    input_file = f"reports/{domain}_web_probe.txt"
    output_file = f"reports/{domain}_fuzzing.txt"
    wordlist = "/usr/share/wordlists/dirb/common.txt"  # Change path if necessary

    if not os.path.exists(wordlist):
        log("[FUZZER] Wordlist not found: install dirb or provide a custom list.")
        return

    if not os.path.exists(input_file):
        log(f"[FUZZER] Web probe file not found: {input_file}")
        return

    try:
        with open(input_file, "r") as f:
            urls = [line.strip() for line in f if line.strip() and line.startswith("http")]

        with open(output_file, "w") as f:
            for url in urls:
                try:
                    log(f"[FUZZER] Fuzzing {url} with gobuster...")
                    result = subprocess.run([
                        "gobuster", "dir",
                        "-u", url,
                        "-w", wordlist,
                        "-t", "40",
                        "-q",
                        "-e",
                        "--no-error"
                    ], capture_output=True, text=True, timeout=180)

                    f.write(f"\nResults for {url}:\n")
                    f.write(result.stdout)
                    log(f"[FUZZER] Fuzzed {url} successfully.")
                except subprocess.TimeoutExpired:
                    log(f"[FUZZER] Timeout expired while fuzzing {url}")
                    f.write(f"\nTimeout while fuzzing {url}\n")
                except Exception as e:
                    log(f"[FUZZER] Exception occurred while fuzzing {url}: {e}")
                    f.write(f"\nError fuzzing {url}: {e}\n")

        log(f"[FUZZER] Fuzzing complete. Results saved to {output_file}")

    except Exception as e:
        log(f"[FUZZER] General exception during fuzzing process: {e}")
