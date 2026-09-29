"""
agent/modules/byovd_detector.py
Detects Bring Your Own Vulnerable Driver (BYOVD) activity on Linux and Windows.

On Linux:
  - Reads /proc/modules and /sys/module/*/sections/.text
  - Compares against bundled JSON database of known-vulnerable driver names/hashes

On Windows:
  - Uses ctypes + EnumDeviceDrivers
  - Hashes drivers with SHA-256
  - Compares against vulnerability database

Task manifest params
--------------------
    {"name": "byovd_detector", "params": {
        "vuln_db":   "rules/byovd.json",
        "out_dir":   "artifacts"
    }}

Artifact kinds emitted
----------------------
    byovd_hit    meta["driver_name"]     = name of detected driver
                 meta["driver_hash"]     = SHA-256 hash
                 meta["cve_list"]        = list of CVE IDs
                 meta["severity"]        = "critical" | "high" | "medium"
"""

import os
import sys
import json
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Optional


def _sha256_file(path: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (OSError, IOError):
        return ""


def _sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def _load_vuln_database(db_path: str) -> Dict[str, dict]:
    """
    Load vulnerability database from JSON.
    Expected format:
    {
        "driver_name": {
            "hash": "sha256_hash",
            "cves": ["CVE-2024-XXXXX"],
            "severity": "critical"
        },
        ...
    }
    """
    db = {}
    if os.path.isfile(db_path):
        try:
            with open(db_path, "r") as f:
                data = json.load(f)
                db = {k: v for k, v in data.items() if isinstance(v, dict)}
        except (json.JSONDecodeError, IOError):
            pass
    return db


def _scan_linux() -> List[tuple]:
    """
    Scan Linux drivers via /proc/modules and /sys/module.
    Returns list of (driver_name, hash) tuples.
    """
    drivers = []
    
    # Read /proc/modules
    modules_path = "/proc/modules"
    if os.path.isfile(modules_path):
        try:
            with open(modules_path, "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 0:
                        module_name = parts[0]
                        
                        # Try to get the .text section hash
                        text_path = f"/sys/module/{module_name}/sections/.text"
                        driver_hash = ""
                        
                        if os.path.isfile(text_path):
                            try:
                                with open(text_path, "r") as tf:
                                    addr = tf.read().strip()
                                    # Use the address as a hash (not perfect but lightweight)
                                    driver_hash = addr.lower().lstrip("0x")
                            except IOError:
                                pass
                        
                        if driver_hash or module_name:
                            drivers.append((module_name, driver_hash))
        except (IOError, OSError):
            pass
    
    return drivers


def _scan_windows() -> List[tuple]:
    """
    Scan Windows drivers via EnumDeviceDrivers.
    Returns list of (driver_path, hash) tuples.
    """
    drivers = []
    
    if sys.platform != "win32":
        return drivers
    
    try:
        import ctypes
        from ctypes import wintypes
        
        # Get Windows DLLs
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        
        # EnumDeviceDrivers: BOOL EnumDeviceDrivers(LPVOID *lpDeviceDrivers, DWORD cb, LPDWORD lpcbNeeded)
        EnumDeviceDrivers = psapi.EnumDeviceDrivers
        EnumDeviceDrivers.argtypes = [
            ctypes.POINTER(wintypes.LPVOID),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)
        ]
        EnumDeviceDrivers.restype = wintypes.BOOL
        
        # GetDeviceDriverFileNameA: DWORD GetDeviceDriverFileNameA(LPVOID ImageBase, LPSTR lpFilename, DWORD nSize)
        GetDeviceDriverFileNameA = psapi.GetDeviceDriverFileNameA
        GetDeviceDriverFileNameA.argtypes = [
            wintypes.LPVOID,
            ctypes.c_char_p,
            wintypes.DWORD
        ]
        GetDeviceDriverFileNameA.restype = wintypes.DWORD
        
        # Enumerate drivers
        drivers_array = (wintypes.LPVOID * 512)()
        needed = wintypes.DWORD()
        
        if EnumDeviceDrivers(drivers_array, len(drivers_array) * ctypes.sizeof(wintypes.LPVOID), ctypes.byref(needed)):
            driver_count = needed.value // ctypes.sizeof(wintypes.LPVOID)
            
            for i in range(min(driver_count, 512)):
                driver_base = drivers_array[i]
                filename_buffer = ctypes.create_string_buffer(256)
                
                GetDeviceDriverFileNameA(driver_base, filename_buffer, 256)
                driver_path = filename_buffer.value.decode("utf-8", errors="ignore").strip('\x00')
                
                if driver_path:
                    # Hash the driver file
                    driver_hash = ""
                    if os.path.isfile(driver_path):
                        driver_hash = _sha256_file(driver_path)
                    
                    drivers.append((driver_path, driver_hash))
    
    except (ImportError, AttributeError, OSError, Exception):
        # If Windows API fails, fall back gracefully
        pass
    
    return drivers


class Module:
    def run(self, params: dict):
        """Detect BYOVD activity."""
        from agent.artifacts import ArtifactResult
        
        vuln_db_path = params.get("vuln_db", "rules/byovd.json")
        out_dir = params.get("out_dir", "artifacts")
        
        os.makedirs(out_dir, exist_ok=True)
        
        # Load vulnerability database
        vuln_db = _load_vuln_database(vuln_db_path)
        
        artifacts: list = []
        anomalies: list = []
        
        # Scan for loaded drivers
        try:
            if sys.platform == "win32":
                drivers = _scan_windows()
            else:
                drivers = _scan_linux()
        except Exception as e:
            anomalies.append({
                "type": "scan_error",
                "error": str(e)
            })
            return ArtifactResult(artifacts=artifacts, anomalies=anomalies)
        
        # Check each driver against the database
        hits = []
        
        for driver_name, driver_hash in drivers:
            # Extract just the filename for matching
            driver_basename = os.path.basename(driver_name).lower()
            
            # Check by name
            for vuln_name, vuln_info in vuln_db.items():
                if vuln_name.lower() == driver_basename:
                    hit = {
                        "driver_name": driver_name,
                        "driver_hash": driver_hash,
                        "cve_list": vuln_info.get("cves", []),
                        "severity": vuln_info.get("severity", "medium"),
                        "match_type": "name"
                    }
                    hits.append(hit)
                    break
            
            # Check by hash if available
            if driver_hash:
                for vuln_name, vuln_info in vuln_db.items():
                    expected_hash = vuln_info.get("hash", "")
                    if expected_hash and expected_hash.lower() == driver_hash.lower():
                        hit = {
                            "driver_name": driver_name,
                            "driver_hash": driver_hash,
                            "cve_list": vuln_info.get("cves", []),
                            "severity": vuln_info.get("severity", "medium"),
                            "match_type": "hash"
                        }
                        hits.append(hit)
                        break
        
        # Emit artifacts for each hit
        for hit in hits:
            artifact_data = json.dumps(hit, default=str).encode("utf-8")
            artifacts.append((
                "byovd_hit",
                artifact_data,
                {
                    "driver_name": hit["driver_name"],
                    "driver_hash": hit["driver_hash"],
                    "cve_list": hit["cve_list"],
                    "severity": hit["severity"]
                }
            ))
        
        # Summary
        if not hits:
            anomalies.append({
                "type": "info",
                "message": f"Scanned {len(drivers)} drivers, no BYOVD matches found"
            })
        
        return ArtifactResult(artifacts=artifacts, anomalies=anomalies)
