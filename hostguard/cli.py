"""
HostGuard-FIM CLI.
"""
import argparse, json, logging, os, sys
from .crypto import BaselineStore
from .scanner import IntegrityChecker
from .reporter import ReportGenerator
from . import __version__

def setup_logging(level, log_file=None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s  %(levelname)-9s %(name)s \u2014 %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ", handlers=handlers)

def load_config(path):
    defaults = {"monitored_paths":["./monitored_files"],"baseline_database":"baseline.json","exclude_dirs":[".git","__pycache__",".venv","node_modules","reports"],"exclude_patterns":["*.pyc","*.log","*.tmp","*.bak"],"exclude_files":["baseline.json","hostguard.log","config.json"],"max_file_size_bytes":104857600,"output":{"dir":"reports"}}
    if path and os.path.exists(path):
        with open(path) as f: defaults.update(json.load(f))
    return defaults

def main():
    print(f"\n{'='*60}\n  HostGuard-FIM v{__version__} | By Deepesh Kumar Mahawar\n{'='*60}\n")
    parser = argparse.ArgumentParser(prog="hostguard",description="HostGuard-FIM \u2014 Host-Based File Integrity Monitor")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", "-c", metavar="FILE", default="config.json")
    parser.add_argument("--output-dir", metavar="DIR")
    parser.add_argument("--log-level", choices=["DEBUG","INFO","WARNING","ERROR"], default="INFO")
    parser.add_argument("--log-file", metavar="FILE")
    sub = parser.add_subparsers(dest="command", required=True)
    bl = sub.add_parser("baseline", help="Create/update the trusted baseline.")
    bl.add_argument("--paths", nargs="+", metavar="PATH")
    ck = sub.add_parser("check", help="Compare filesystem against baseline.")
    ck.add_argument("--fail-on-alert", action="store_true", help="Exit code 1 if violations found.")
    args = parser.parse_args()
    setup_logging(args.log_level, args.log_file)
    config = load_config(args.config)
    if args.output_dir: config.setdefault("output",{})["dir"] = args.output_dir
    if args.command == "baseline" and hasattr(args,"paths") and args.paths:
        config["monitored_paths"] = args.paths
    store = BaselineStore(config.get("baseline_database", "baseline.json"))
    checker = IntegrityChecker(config, store)
    log = logging.getLogger("hostguard")
    if args.command == "baseline":
        stats = checker.create_baseline()
        log.info("Baseline complete: %d files in %.3fs", stats.files_hashed, stats.scan_duration)
    elif args.command == "check":
        try: alerts, stats = checker.check_integrity()
        except FileNotFoundError as e: log.error(str(e)); sys.exit(1)
        reporter = ReportGenerator(config["output"].get("dir","reports"))
        try: _, meta = store.load()
        except FileNotFoundError: meta = {}
        paths = reporter.generate_all(alerts, stats, meta)
        for fmt, p in paths.items(): log.info("  [%s] %s", fmt.upper(), p)
        total = sum(stats.alerts_by_severity.values())
        crit = stats.alerts_by_severity.get("CRITICAL",0)
        if total: log.warning("%d violations found (%d Critical).", total, crit)
        else: log.info("\u2705 Integrity check passed \u2014 system clean.")
        if args.fail_on_alert and total > 0: sys.exit(1)

if __name__ == "__main__": main()
