from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from .models import Severity, ThreatCategory, ThreatFinding
from .utils import _hidden_startupinfo, compute_sha256

KNOWN_MALICIOUS_FILENAMES = {
    "xmrig.exe": ("Phần mềm đào coin XMRig", Severity.CRITICAL),
    "winring0x64.sys": ("Driver nhân WinRing0 (thường bị mã đào coin lợi dụng)", Severity.HIGH),
    "sysmon.py": ("Script watchdog ẩn Task Manager (SysMon.py)", Severity.CRITICAL),
    "phoenixminer.exe": ("Phần mềm đào coin PhoenixMiner", Severity.CRITICAL),
    "lolminer.exe": ("Phần mềm đào coin lolMiner", Severity.CRITICAL),
    "gminer.exe": ("Phần mềm đào coin GMiner", Severity.CRITICAL),
    "t-rex.exe": ("Phần mềm đào coin T-Rex", Severity.CRITICAL),
    "nbminer.exe": ("Phần mềm đào coin NBMiner", Severity.CRITICAL),
    "rigel.exe": ("Phần mềm đào coin Rigel", Severity.CRITICAL),
}

SCRIPT_EXTS = {".ps1", ".py", ".bat", ".cmd", ".vbs", ".js", ".hta"}
BINARY_EXTS = {".exe", ".dll", ".sys", ".scr"}

SCRIPT_SIGNATURES: List[Tuple[re.Pattern[bytes], str, Severity]] = [
    (re.compile(rb"stratum\+tcp://|stratum\+ssl://", re.I), "Chứa địa chỉ pool đào coin (Stratum)", Severity.CRITICAL),
    (re.compile(rb"add-mppreference\s+.*-exclusion", re.I), "Lệnh tự thêm ngoại lệ qua mặt Windows Defender", Severity.CRITICAL),
    (re.compile(rb"__pyarmor__|pyarmor_runtime", re.I), "Mã Python bị mã hóa/che giấu bằng PyArmor", Severity.HIGH),
    (re.compile(rb"(taskmgr\.exe|processhacker|procexp).*(kill|terminate|suspend|stop)", re.I | re.S), "Chứa mã tự ẩn/chống Task Manager", Severity.CRITICAL),
    (re.compile(rb"(frombase64string|encodedcommand).*(iex|invoke-expression|downloadstring)", re.I | re.S), "Script PowerShell mã hóa Base64 tải & chạy mã độc", Severity.CRITICAL),
    (re.compile(rb"(login data|local state|cryptunprotectdata|dpapi).*(discord|wallet|metamask|seed|cookie)", re.I | re.S), "Dấu hiệu Infostealer đánh cắp mật khẩu/cookie/ví crypto", Severity.CRITICAL),
]

BINARY_SIGNATURES: List[Tuple[re.Pattern[bytes], str, Severity]] = [
    (re.compile(rb"stratum\+tcp://|stratum\+ssl://", re.I), "Chứa chuỗi giao thức đào coin Stratum", Severity.CRITICAL),
    (
        re.compile(rb"xmrig\.com|randomx_alloc_cache|randomx_init_dataset|--donate-level|moneroocean|cryptonight/r", re.I),
        "Chứa chuỗi đặc trưng của mã đào coin XMRig",
        Severity.CRITICAL,
    ),
]


def _find_mpcmdrun() -> Optional[Path]:
    platform_dir = Path(r"C:\ProgramData\Microsoft\Windows Defender\Platform")
    if platform_dir.is_dir():
        versions = sorted(platform_dir.iterdir(), reverse=True)
        for v in versions:
            candidate = v / "MpCmdRun.exe"
            if candidate.is_file():
                return candidate
    fallback = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")
    return fallback if fallback.is_file() else None


def scan_with_defender_cli(target_path: str | Path, timeout: int = 120) -> Tuple[bool, str]:
    """Run Windows Defender MpCmdRun.exe custom scan on a file or folder. Returns (threat_found, output)."""
    mp = _find_mpcmdrun()
    if not mp:
        return False, "Không tìm thấy MpCmdRun.exe của Windows Defender."
    try:
        proc = subprocess.run(
            [str(mp), "-Scan", "-ScanType", "3", "-File", str(target_path), "-DisableRemediation"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = (proc.stdout + "\n" + proc.stderr).strip()
        # MpCmdRun returns exit code 2 when threats are found
        threat_found = proc.returncode == 2 or "found" in output.lower() and "no threats" not in output.lower()
        return threat_found, output
    except subprocess.TimeoutExpired:
        return False, "Quét Windows Defender quá thời gian chờ (timeout)."
    except Exception as exc:
        return False, f"Lỗi khi gọi Windows Defender: {exc}"


def check_virustotal_hash(sha256: str, api_key: str) -> Dict[str, Any]:
    """Look up a file SHA-256 hash on VirusTotal API v3."""
    if not sha256 or not api_key:
        return {"ok": False, "error": "Thiếu SHA-256 hoặc VirusTotal API Key."}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        resp = requests.get(url, headers={"x-apikey": api_key.strip()}, timeout=15)
        if resp.status_code == 404:
            return {"ok": True, "found": False, "message": "Chưa có dữ liệu hash này trên VirusTotal."}
        if resp.status_code == 401:
            return {"ok": False, "error": "VirusTotal API Key không hợp lệ."}
        if resp.status_code == 429:
            return {"ok": False, "error": "Vượt quá giới hạn request miễn phí của VirusTotal (4 req/phút)."}
        if resp.status_code != 200:
            return {"ok": False, "error": f"HTTP {resp.status_code}"}
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "ok": True,
            "found": True,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "name": data.get("meaningful_name", ""),
            "link": f"https://www.virustotal.com/gui/file/{sha256}",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def analyze_single_file(file_path: Path) -> Optional[ThreatFinding]:
    """Run static heuristic checks on a single file."""
    try:
        if not file_path.is_file():
            return None
        size = file_path.stat().st_size
        if size == 0 or size > 80 * 1024 * 1024:
            return None

        name_lower = file_path.name.lower()
        ext = file_path.suffix.lower()
        reasons: List[str] = []
        severity = Severity.INFO

        # 1. Known malicious filename
        if name_lower in KNOWN_MALICIOUS_FILENAMES:
            desc, sev = KNOWN_MALICIOUS_FILENAMES[name_lower]
            reasons.append(desc)
            if sev.rank > severity.rank:
                severity = sev

        # 2. Content heuristics for scripts & binaries (read up to 4 MB)
        if ext in SCRIPT_EXTS or ext in BINARY_EXTS:
            try:
                with file_path.open("rb") as f:
                    sample = f.read(4 * 1024 * 1024)
            except OSError:
                sample = b""

            if sample:
                sigs = SCRIPT_SIGNATURES if ext in SCRIPT_EXTS else BINARY_SIGNATURES
                for pat, desc, sev in sigs:
                    if pat.search(sample):
                        reasons.append(desc)
                        if sev.rank > severity.rank:
                            severity = sev

        if not reasons:
            return None

        sha = compute_sha256(file_path)
        return ThreatFinding(
            title=f"Suspicious File: {file_path.name}",
            category=ThreatCategory.FILE,
            severity=severity,
            target=str(file_path),
            reason="; ".join(reasons),
            details={"path": str(file_path), "sha256": sha, "size": size},
            title_key="f_file_t",
            title_args={"name": file_path.name},
        )
    except OSError:
        return None


def scan_path_heuristics(
    target: str | Path,
    progress_cb: Optional[Callable[[int, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
    max_files: int = 5000,
) -> Tuple[List[ThreatFinding], int]:
    """Scan a file or folder recursively using static heuristics."""
    path = Path(target)
    findings: List[ThreatFinding] = []
    scanned = 0

    if path.is_file():
        scanned = 1
        if progress_cb:
            progress_cb(1, str(path))
        f = analyze_single_file(path)
        if f:
            findings.append(f)
        return findings, scanned

    if not path.is_dir():
        return findings, 0

    for root, dirs, files in os.walk(path):
        if cancel_event and cancel_event.is_set():
            break
        # Skip huge benign cache/git directories
        dirs[:] = [d for d in dirs if d.lower() not in {".git", "node_modules", "__pycache__", ".venv", "winsxs"}]
        for fname in files:
            if cancel_event and cancel_event.is_set():
                break
            if scanned >= max_files:
                return findings, scanned
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in SCRIPT_EXTS and ext not in BINARY_EXTS and fname.lower() not in KNOWN_MALICIOUS_FILENAMES:
                continue
            scanned += 1
            if progress_cb and (scanned % 10 == 0 or scanned == 1):
                progress_cb(scanned, str(fpath))
            finding = analyze_single_file(fpath)
            if finding:
                findings.append(finding)

    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings, scanned


def quick_scan_hotspot_folders(
    progress_cb: Optional[Callable[[int, str], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> Tuple[List[ThreatFinding], int]:
    """Scan common malware drop hotspots (SystemHealth, Temp, Desktop, Startup, Downloads)."""
    hotspots = [
        Path(r"C:\Windows\SystemHealth"),
        Path(os.environ.get("TEMP", "")),
        Path(r"C:\Windows\Temp"),
        Path.home() / "Desktop",
        Path.home() / "Downloads",
    ]
    all_findings: List[ThreatFinding] = []
    total_scanned = 0
    for hs in hotspots:
        if cancel_event and cancel_event.is_set():
            break
        if hs.is_dir():
            fs, cnt = scan_path_heuristics(hs, progress_cb=progress_cb, cancel_event=cancel_event, max_files=800)
            all_findings.extend(fs)
            total_scanned += cnt
    all_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return all_findings, total_scanned
