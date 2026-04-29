#!/usr/bin/env python3
"""
net-vuln-scanner/scheduler.py
Sets up recurring scans via cron (Linux/macOS) or Windows Task Scheduler.

Usage:
    # Install a daily cron job at 02:00
    python scheduler.py install --target 192.168.1.0/24 --frequency daily --time 02:00

    # Install a weekly job on Monday at 03:30
    python scheduler.py install --target 10.0.0.0/24 --frequency weekly --day monday --time 03:30

    # Remove an installed cron job
    python scheduler.py remove --target 192.168.1.0/24

    # List all scanner cron jobs
    python scheduler.py list

    # Run a single scan immediately (no scheduling)
    python scheduler.py run --target 192.168.1.0/24
"""

import argparse
import os
import platform
import re
import subprocess
import sys
import tempfile
import textwrap
from datetime import datetime
from pathlib import Path

SCANNER_MARKER = "# NET-VULN-SCANNER"
SCRIPT_DIR = Path(__file__).parent.resolve()
SCANNER_PATH = SCRIPT_DIR / "scanner.py"
REPORTS_DIR = SCRIPT_DIR / "reports"

DAY_MAP = {
    "sunday": 0, "monday": 1, "tuesday": 2,
    "wednesday": 3, "thursday": 4, "friday": 5, "saturday": 6,
}

FREQ_CRON = {
    "hourly":  "{minute} * * * *",
    "daily":   "{minute} {hour} * * *",
    "weekly":  "{minute} {hour} * * {weekday}",
    "monthly": "{minute} {hour} 1 * *",
}


#Helpers

def _is_windows() -> bool:
    return platform.system() == "Windows"


def _python_exe() -> str:
    """Return the current Python interpreter path."""
    return sys.executable


def _safe_target(target: str) -> str:
    """Make a target string safe for use as a filename."""
    return re.sub(r"[^\w\-.]", "_", target)


def _report_path(target: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    return REPORTS_DIR / f"scan_{_safe_target(target)}_{date_str}.html"


def _build_scan_command(target: str, extra_args: str = "") -> str:
    """Build the full scanner command line."""
    report_dir = REPORTS_DIR.resolve()
    cmd = (
        f'{_python_exe()} "{SCANNER_PATH}" '
        f'--target {target} '
        f'--output "{report_dir}/scan_{_safe_target(target)}_$(date +%Y%m%d_%H%M%S).html"'
    )
    if extra_args:
        cmd += f" {extra_args}"
    # Pipe YES to bypass interactive prompt in unattended mode
    cmd = f'echo YES | {cmd}'
    return cmd


def _build_scan_command_windows(target: str, extra_args: str = "") -> str:
    report_dir = REPORTS_DIR.resolve()
    timestamp_var = r'%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%'
    cmd = (
        f'echo YES | "{_python_exe()}" "{SCANNER_PATH}" '
        f'--target {target} '
        f'--output "{report_dir}\\scan_{_safe_target(target)}_{timestamp_var}.html"'
    )
    if extra_args:
        cmd += f" {extra_args}"
    return cmd


#Cron (Linux / macOS)

def _read_crontab() -> str:
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        return result.stdout if result.returncode == 0 else ""
    except FileNotFoundError:
        return ""


def _write_crontab(content: str) -> bool:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cron", delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        result = subprocess.run(["crontab", tmp], capture_output=True)
        return result.returncode == 0
    finally:
        os.unlink(tmp)


def _build_cron_expression(frequency: str, time_str: str, day: str) -> str:
    hh, mm = time_str.split(":")
    template = FREQ_CRON[frequency]
    weekday = DAY_MAP.get(day.lower(), 1)
    return template.format(hour=int(hh), minute=int(mm), weekday=weekday)


def install_cron(target: str, frequency: str, time_str: str, day: str, extra_args: str) -> None:
    cron_expr = _build_cron_expression(frequency, time_str, day)
    cmd = _build_scan_command(target, extra_args)
    job_line = f"{cron_expr} {cmd} {SCANNER_MARKER} target={target}"

    current = _read_crontab()
    # Remove any existing job for this target
    lines = [l for l in current.splitlines() if not (SCANNER_MARKER in l and f"target={target}" in l)]
    lines.append(job_line)
    new_cron = "\n".join(lines) + "\n"

    if _write_crontab(new_cron):
        print(f"✅ Cron job installed: [{cron_expr}] → {target}")
        print(f"   Reports saved to: {REPORTS_DIR}/")
        print(f"   Full line: {job_line}")
    else:
        print("❌ Failed to write crontab. Try running: crontab -e")


def remove_cron(target: str) -> None:
    current = _read_crontab()
    lines = [l for l in current.splitlines() if not (SCANNER_MARKER in l and f"target={target}" in l)]
    new_cron = "\n".join(lines) + "\n"
    if _write_crontab(new_cron):
        print(f"✅ Cron job removed for target: {target}")
    else:
        print("❌ Failed to update crontab.")


def list_cron() -> None:
    current = _read_crontab()
    jobs = [l for l in current.splitlines() if SCANNER_MARKER in l]
    if not jobs:
        print("No net-vuln-scanner cron jobs installed.")
        return
    print(f"Found {len(jobs)} scheduled scan(s):\n")
    for job in jobs:
        print(f"  {job}")


#Windows Task Scheduler 

def install_windows(target: str, frequency: str, time_str: str, day: str, extra_args: str) -> None:
    task_name = f"NetVulnScanner_{_safe_target(target)}"
    cmd = _build_scan_command_windows(target, extra_args)

    sched_map = {
        "hourly":  "HOURLY",
        "daily":   "DAILY",
        "weekly":  "WEEKLY",
        "monthly": "MONTHLY",
    }
    schedule = sched_map.get(frequency, "DAILY")

    # Create a .bat wrapper (schtasks needs a simple executable)
    bat_path = SCRIPT_DIR / f"_task_{_safe_target(target)}.bat"
    bat_content = textwrap.dedent(f"""\
        @echo off
        {cmd}
    """)
    bat_path.write_text(bat_content)

    schtasks_cmd = [
        "schtasks", "/Create", "/F",
        "/TN", task_name,
        "/TR", str(bat_path),
        "/SC", schedule,
        "/ST", time_str,
    ]
    if frequency == "weekly":
        schtasks_cmd += ["/D", day[:3].upper()]

    result = subprocess.run(schtasks_cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✅ Windows Task '{task_name}' created ({schedule} at {time_str})")
        print(f"   Batch file: {bat_path}")
        print(f"   Reports:    {REPORTS_DIR}\\")
    else:
        print(f"❌ schtasks error: {result.stderr}")
        print(f"   Batch wrapper saved to: {bat_path}")
        print(f"   You can add it manually via Task Scheduler GUI.")


def remove_windows(target: str) -> None:
    task_name = f"NetVulnScanner_{_safe_target(target)}"
    result = subprocess.run(
        ["schtasks", "/Delete", "/TN", task_name, "/F"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"✅ Task '{task_name}' removed.")
    else:
        print(f"❌ Could not remove task: {result.stderr}")


def list_windows() -> None:
    result = subprocess.run(
        ["schtasks", "/Query", "/FO", "LIST", "/V"],
        capture_output=True, text=True
    )
    lines = result.stdout.splitlines()
    in_task = False
    for line in lines:
        if "NetVulnScanner" in line:
            in_task = True
        if in_task:
            print(line)
            if line.strip() == "":
                in_task = False


# ── Immediate Run ─────────────────────────────────────────────────────────────

def run_now(target: str, extra_args: str) -> None:
    """Invoke the scanner immediately via subprocess."""
    report = _report_path(target)
    py = _python_exe()
    cmd_parts = [py, str(SCANNER_PATH), "--target", target, "--output", str(report)]
    if extra_args:
        cmd_parts += extra_args.split()

    print(f"Running scan on {target} → {report}")
    # Write YES to stdin automatically
    result = subprocess.run(cmd_parts, input="YES\n", text=True)
    sys.exit(result.returncode)


#CLI 

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scheduler.py",
        description="Schedule recurring net-vuln-scanner scans",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scheduler.py install --target 192.168.1.0/24 --frequency daily --time 02:00
  python scheduler.py install --target 10.0.0.0/24 --frequency weekly --day monday --time 03:30
  python scheduler.py remove  --target 192.168.1.0/24
  python scheduler.py list
  python scheduler.py run     --target 10.0.0.1
        """,
    )
    sub = p.add_subparsers(dest="command", required=True)

    # install
    inst = sub.add_parser("install", help="Install a scheduled scan")
    inst.add_argument("--target", required=True)
    inst.add_argument("--frequency", choices=["hourly", "daily", "weekly", "monthly"], default="daily")
    inst.add_argument("--time", default="02:00", help="HH:MM (24h)")
    inst.add_argument("--day", default="monday", help="Day of week for weekly scans")
    inst.add_argument("--extra-args", default="", help="Extra args passed to scanner.py")

    # remove
    rem = sub.add_parser("remove", help="Remove a scheduled scan")
    rem.add_argument("--target", required=True)

    # list
    sub.add_parser("list", help="List scheduled scans")

    # run
    run = sub.add_parser("run", help="Run a scan immediately")
    run.add_argument("--target", required=True)
    run.add_argument("--extra-args", default="")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    is_win = _is_windows()

    if args.command == "install":
        if is_win:
            install_windows(args.target, args.frequency, args.time, args.day, args.extra_args)
        else:
            install_cron(args.target, args.frequency, args.time, args.day, args.extra_args)

    elif args.command == "remove":
        if is_win:
            remove_windows(args.target)
        else:
            remove_cron(args.target)

    elif args.command == "list":
        if is_win:
            list_windows()
        else:
            list_cron()

    elif args.command == "run":
        run_now(args.target, args.extra_args)


if __name__ == "__main__":
    main()
