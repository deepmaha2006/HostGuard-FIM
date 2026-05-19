"""
Dual SHA-256 + MD5 hashing with atomic baseline persistence.
"""
import hashlib, json, logging, os, platform, stat
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class FileRecord:
    path: str; sha256: str; md5: str; size_bytes: int; permissions: str
    owner_uid: int; group_gid: int; mtime: float; ctime: float
    last_scanned: str; is_executable: bool; platform: str
    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls, d):
        fields = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in d.items() if k in fields})

@dataclass
class AlertRecord:
    timestamp: str; severity: str; event_type: str; path: str; description: str
    old_hash: Optional[str]=None; new_hash: Optional[str]=None
    old_permissions: Optional[str]=None; new_permissions: Optional[str]=None
    mitre_technique: Optional[str]=None
    def to_dict(self): return asdict(self)

class CryptoEngine:
    CHUNK = 65536
    @classmethod
    def hash_file(cls, path):
        sha, md5 = hashlib.sha256(), hashlib.md5()
        with open(path, "rb") as f:
            while chunk := f.read(cls.CHUNK): sha.update(chunk); md5.update(chunk)
        return sha.hexdigest(), md5.hexdigest()
    @classmethod
    def capture(cls, path):
        try:
            st = os.stat(path)
            sha256, md5 = cls.hash_file(path)
            is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            return FileRecord(path=os.path.abspath(path),sha256=sha256,md5=md5,size_bytes=st.st_size,
                permissions=oct(st.st_mode),owner_uid=st.st_uid,group_gid=st.st_gid,
                mtime=st.st_mtime,ctime=st.st_ctime,last_scanned=datetime.utcnow().isoformat()+"Z",
                is_executable=is_exec,platform=platform.system())
        except (FileNotFoundError, PermissionError, OSError) as e:
            logger.debug("Cannot capture %s: %s", path, e); return None

class BaselineStore:
    VERSION = "2.0"
    def __init__(self, db_path): self.db_path = db_path
    def save(self, records, scan_roots):
        tmp = self.db_path + ".tmp"
        data = {"meta":{"version":self.VERSION,"created_at":datetime.utcnow().isoformat()+"Z","tool":"HostGuard-FIM v2.0","author":"Deepesh Kumar Mahawar","scan_roots":scan_roots,"total_files":len(records)},"files":{p:r.to_dict() for p,r in records.items()}}
        with open(tmp, "w", encoding="utf-8") as f: json.dump(data, f, indent=2)
        os.replace(tmp, self.db_path)
        logger.info("Baseline saved: %d files \u2192 %s", len(records), self.db_path)
    def load(self):
        if not os.path.isfile(self.db_path):
            raise FileNotFoundError(f"Baseline not found: {self.db_path}. Run 'hostguard baseline' first.")
        with open(self.db_path, "r", encoding="utf-8") as f: data = json.load(f)
        records = {}
        for path, rec_d in data.get("files", {}).items():
            try: records[path] = FileRecord.from_dict(rec_d)
            except Exception as e: logger.warning("Bad record %s: %s", path, e)
        return records, data.get("meta", {})
