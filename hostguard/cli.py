"""
HostGuard-FIM CLI entry point.
"""
import argparse
import json
import logging
import os
import sys

from .crypto import BaselineStore
from .scanner import IntegrityChecker
from .reporter import ReportGenerator
from . import __version__


def setup_logging(level: str, log_file: str = None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-9s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        handlers=handlers,
    )


def load_config(path: str) -> dict:
    defaults = {
        "monitored_paths": ["./monitored_files"],
        "baseline_database": "baseline.json",
        "exclude_dirs": [".git", "__pycache__", ".venv", "node_modules"],
        "exclude_patterns": ["*.pyc", "*.log", "*.tmp", "*.bak"],
        "exclude_files": ["baseline.json", "hostguard.log", "config.json"],
        "max_file_size_bytes": 104857600,
        "output": {"dir": "reports"},
    }
    if path and os.path.exists(path):
        with open(path) as f:
            user = json.load(f)
            defaults.update(user)
    return defaults


def print_banner():
    print(f"""
+----------------------------------------------------------+
|          HostGuard-FIM  v{__version__}                         |
|    Host-Based File Integrity Monitor (HIDS/FIM)          |
|              By Deepesh Kumar Mahawar                    |
+----------------------------------------------------------+
""")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="hostguard",
        description="HostGuard-FIM - Industrial-Grade Host File Integrity Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  hostguard baseline --paths /var/www /etc/nginx
  hostguard check
  hostguard check --output-dir /var/reports --log-level DEBUG
  hostguard baseline --config custom.json
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", metavar="FILE", default="config.json",
                        help="Path to JSON configuration file (default: config.json).")
    parser.add_argument("--output-dir", metavar="DIR", help="Report output directory.")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    parser.add_argument("--log-file", metavar="FILE", help="Write logs to this file.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline
    bl = subparsers.add_parser("baseline", help="Scan directories and create/update the trusted baseline.")
    bl.add_argument("--paths", nargs="+", metavar="PATH", help="Override monitored paths.")

    # check
    ck = subparsers.add_parser("check", help="Compare live filesystem against stored baseline.")
    ck.add_argument("--fail-on-alert", action="store_true",
                    help="Exit with code 1 if any integrity violations are found.")

    args = parser.parse_args()
    setup_logging(args.log_level, args.log_file)

    config = load_config(args.config)
    if args.output_dir:
        config.setdefault("output", {})["dir"] = args.output_dir

    if args.command == "baseline" and args.paths:
        config["monitored_paths"] = args.paths

    store   = BaselineStore(config.get("baseline_database", "baseline.json"))
    checker = IntegrityChecker(config, store)
    log     = logging.getLogger("hostguard")

    if args.command == "baseline":
        log.info("Creating trusted baseline...")
        stats = checker.create_baseline()
        log.info("Baseline created - %d files hashed in %.3fs", stats.files_hashed, stats.scan_duration)

    elif args.command == "check":
        try:
            alerts, stats = checker.check_integrity()
        except FileNotFoundError as e:
            log.error(str(e))
            sys.exit(1)

        reporter = ReportGenerator(config["output"].get("dir", "reports"))
        try:
            _, meta = store.load()
        except FileNotFoundError:
            meta = {}
        paths = reporter.generate_all(alerts, stats, meta)

        log.info("Reports generated:")
        for fmt, p in paths.items():
            log.info("  [%s] %s", fmt.upper(), p)

        crit = stats.alerts_by_severity.get("CRITICAL", 0)
        total = sum(stats.alerts_by_severity.values())
        if total:
            log.warning("%d integrity violations found (%d Critical).", total, crit)
        else:
            log.info("[PASS] Integrity check passed - system is clean.")

        if args.fail_on_alert and total > 0:
            sys.exit(1)


if __name__ == "__main__":
    main()
