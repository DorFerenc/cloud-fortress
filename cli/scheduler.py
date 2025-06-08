#!/usr/bin/env python3
"""
scheduler.py

Simple loop that calls your CLI entrypoint every 5 minutes.
Adds logging of next run time.
"""

import time
import subprocess
import sys
import os
from datetime import datetime, timedelta

# Use the same Python interpreter you're running now
PYTHON_EXEC = sys.executable

# scheduler.py lives in the 'cli' folder next to main.py,
# so we just join __file__'s dir with 'main.py'
CLI_SCRIPT = os.path.join(os.path.dirname(__file__), "main.py")

# Adjust flags as needed
CLI_ARGS = ["--mode", "real", "--send"]


def run_scan():
    """Invoke the CLI scan as a subprocess."""
    cmd = [PYTHON_EXEC, CLI_SCRIPT] + CLI_ARGS
    start_time = datetime.now()
    print(f"[{start_time.strftime('%Y-%m-%d %H:%M:%S')}] Starting scan: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout, end="")
        if result.stderr:
            print("STDERR:", result.stderr, file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"[!] Scan failed (exit {e.returncode}):", e.stderr or e.stdout, file=sys.stderr)
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    print(f"[{end_time.strftime('%Y-%m-%d %H:%M:%S')}] Scan finished in {duration:.1f}s")
    return end_time


def main():
    print("Scheduler started. Press Ctrl+C to stop.")
    try:
        # initial run
        last_run = run_scan()
        while True:
            # compute next run target
            next_run = last_run + timedelta(minutes=5)
            now = datetime.now()
            wait = (next_run - now).total_seconds()
            if wait > 0:
                print(f"Next scan at {next_run.strftime('%Y-%m-%d %H:%M:%S')} ({wait:.0f}s from now)")
                time.sleep(wait)
            else:
                # if we're already past the scheduled time, run immediately
                print("Missed scheduled time, running scan now...")
            last_run = run_scan()
    except KeyboardInterrupt:
        print("\nScheduler stopped by user.")

if __name__ == "__main__":
    main()
