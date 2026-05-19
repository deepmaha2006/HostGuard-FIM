"""
File scanner and integrity checker.
"""
import fnmatch, logging, os, time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List
from .crypto import CryptoEngine, BaselineStore, AlertRecord

logger = logging.getLogger(__name__)

@dataclass
class ScanStats:
    scan_start: str = ""; scan_end: str = ""; scan_duration: float = 0.0
    files_scanned: int = 0; files_hashed: int = 0; bytes_hashed: int = 0; baseline_files: int = 0
    alerts_by_type: dict = field(default_factory=dict)
    alerts_by_severity: dict = field(default_factory=lambda: {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0})

class FileScanner:
    def __init__(self, config):
        self.exclude_dirs = set(config.get("exclude_dirs", [".git","__pycache__",".venv","node_modules","reports"]))
        self.exclude_patterns = config.get("exclude_patterns", ["*.pyc","*.log","*.tmp","*.bak"])
        self.exclude_files = set(config.get("exclude_files", ["baseline.json","hostguard.log","config.json"]))
        self.max_size = config.get("max_file_size_bytes", 104857600)
    def scan_directory(self, root):
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in self.exclude_dirs and not d.startswith(".")]
            for filename in filenames:
                abs_path = os.path.abspath(os.path.join(dirpath, filename))
                if filename in self.exclude_files: continue
                if any(fnmatch.fnmatch(filename, pat) for pat in self.exclude_patterns): continue
                try:
                    if os.path.getsize(abs_path) > self.max_size: continue
                except OSError: continue
                rec = CryptoEngine.capture(abs_path)
                if rec: yield abs_path, rec

class IntegrityChecker:
    MITRE_MAP = {"MODIFIED":"T1565.001 - Stored Data Manipulation","DELETED":"T1070.004 - File Deletion","CREATED":"T1105 - Ingress Tool Transfer","PERMISSION_CHANGE":"T1222 - File Permission Modification","EXEC_ADDED":"T1574 - Hijack Execution Flow"}
    def __init__(self, config, store):
        self.config = config; self.store = store
        self.scanner = FileScanner(config)
        self.scan_roots = config.get("monitored_paths", ["./monitored_files"])
    def create_baseline(self):
        stats = ScanStats(scan_start=datetime.utcnow().isoformat()+"Z")
        t0 = time.perf_counter(); records = {}
        for root in self.scan_roots:
            if not os.path.exists(root): logger.warning("Creating: %s", root); os.makedirs(root, exist_ok=True)
            for path, rec in self.scanner.scan_directory(root):
                records[path] = rec; stats.files_hashed += 1; stats.bytes_hashed += rec.size_bytes
        self.store.save(records, self.scan_roots)
        stats.files_scanned = stats.files_hashed; stats.scan_end = datetime.utcnow().isoformat()+"Z"; stats.scan_duration = time.perf_counter() - t0
        logger.info("Baseline: %d files | %s bytes | %.2fs", stats.files_hashed, f"{stats.bytes_hashed:,}", stats.scan_duration)
        return stats
    def check_integrity(self):
        stats = ScanStats(scan_start=datetime.utcnow().isoformat()+"Z")
        t0 = time.perf_counter()
        baseline, meta = self.store.load()
        stats.baseline_files = len(baseline)
        logger.info("Checking against baseline (%d files)", len(baseline))
        alerts: List[AlertRecord] = []; live_paths = set()
        for root in self.scan_roots:
            if not os.path.exists(root): continue
            for path, live in self.scanner.scan_directory(root):
                stats.files_scanned += 1; live_paths.add(path)
                if path not in baseline:
                    sev = "HIGH" if live.is_executable else "MEDIUM"
                    alerts.append(self._alert(sev, "CREATED", path, f"New {'executable ' if live.is_executable else ''}file outside baseline.", new_hash=live.sha256))
                else:
                    old = baseline[path]
                    if old.sha256 != live.sha256:
                        alerts.append(self._alert("CRITICAL","MODIFIED",path,f"Hash mismatch: {old.sha256[:16]}... \u2192 {live.sha256[:16]}...",old_hash=old.sha256,new_hash=live.sha256))
                    elif not old.is_executable and live.is_executable:
                        alerts.append(self._alert("HIGH","EXEC_ADDED",path,f"File became executable. {old.permissions} \u2192 {live.permissions}.",old_hash=old.sha256,new_hash=live.sha256,old_perm=old.permissions,new_perm=live.permissions))
                    elif old.permissions != live.permissions:
                        alerts.append(self._alert("MEDIUM","PERMISSION_CHANGE",path,f"Permissions: {old.permissions} \u2192 {live.permissions}.",old_hash=old.sha256,new_hash=live.sha256,old_perm=old.permissions,new_perm=live.permissions))
        for base_path in baseline:
            if base_path not in live_paths:
                sev = "CRITICAL" if baseline[base_path].is_executable else "HIGH"
                alerts.append(self._alert(sev,"DELETED",base_path,"Previously tracked file deleted or moved.",old_hash=baseline[base_path].sha256))
        for a in alerts:
            stats.alerts_by_type[a.event_type] = stats.alerts_by_type.get(a.event_type,0)+1
            stats.alerts_by_severity[a.severity] = stats.alerts_by_severity.get(a.severity,0)+1
        stats.scan_end = datetime.utcnow().isoformat()+"Z"; stats.scan_duration = time.perf_counter()-t0
        logger.info("Scan: %d files | %d alerts | %.2fs", stats.files_scanned, len(alerts), stats.scan_duration)
        return alerts, stats
    def _alert(self, severity, event_type, path, description, old_hash=None, new_hash=None, old_perm=None, new_perm=None):
        a = AlertRecord(timestamp=datetime.utcnow().isoformat()+"Z",severity=severity,event_type=event_type,path=path,description=description,old_hash=old_hash,new_hash=new_hash,old_permissions=old_perm,new_permissions=new_perm,mitre_technique=self.MITRE_MAP.get(event_type))
        logger.warning("[%s] [%s] %s \u2014 %s", severity, event_type, path, description)
        return a
