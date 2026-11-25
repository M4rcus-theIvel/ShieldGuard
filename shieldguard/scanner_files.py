from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import requests

from .models import Severity, ThreatCategory, ThreatFinding
from .utils import _hidden_startupinfo, compile_feed_regex, compute_sha256, load_threat_feed

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

SCRIPT_EXTS = {".ps1", ".py", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".wsh"}
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


_FILE_FEED_CACHE: Tuple[Any, Dict[str, Any]] = (None, {})


def _parse_severity(val: str, default: Severity = Severity.HIGH) -> Severity:
    try:
        return Severity(str(val).upper())
    except ValueError:
        return default


def _norm_path_variants(raw_path: str | Path) -> Set[str]:
    p_str = str(raw_path)
    variants: Set[str] = {os.path.normcase(os.path.abspath(p_str))}
    try:
        variants.add(os.path.normcase(str(Path(p_str).resolve())))
    except OSError:
        pass
    return variants


def _get_file_feed_rules() -> Dict[str, Any]:
    global _FILE_FEED_CACHE
    feed = load_threat_feed()
    env_key = (
        os.environ.get("APPDATA", ""),
        os.environ.get("TEMP", ""),
        os.environ.get("LOCALAPPDATA", ""),
    )
    cache_key = (id(feed), env_key)
    if _FILE_FEED_CACHE[0] == cache_key:
        return _FILE_FEED_CACHE[1]

    sha256_iocs: Dict[str, Tuple[str, Severity]] = {}
    for h, info in (feed.get("sha256_iocs") or {}).items():
        if isinstance(info, dict) and h:
            sha256_iocs[str(h).lower()] = (
                str(info.get("name") or "Known Malware"),
                _parse_severity(str(info.get("severity", "CRITICAL")), Severity.CRITICAL),
            )

    filenames: Dict[str, Tuple[str, Severity]] = {}
    for fname, entry in (feed.get("malicious_filenames") or {}).items():
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            filenames[str(fname).lower()] = (str(entry[0]), _parse_severity(str(entry[1]), Severity.CRITICAL))

    malicious_paths: Dict[str, Tuple[str, Severity]] = {}
    path_basenames: Set[str] = set()
    for item in feed.get("malicious_file_paths") or []:
        if not isinstance(item, dict) or not item.get("path"):
            continue
        expanded = os.path.expandvars(str(item["path"]))
        reason = str(item.get("reason") or "Tệp nằm tại đường dẫn mã độc đã biết")
        sev = _parse_severity(str(item.get("severity", "HIGH")), Severity.HIGH)
        path_basenames.add(Path(expanded).name.lower())
        for variant in _norm_path_variants(expanded):
            malicious_paths[variant] = (reason, sev)

    script_sigs: List[Tuple[re.Pattern[bytes], str, Severity]] = []
    for item in feed.get("script_signatures") or []:
        if not isinstance(item, dict):
            continue
        pat = compile_feed_regex(str(item.get("pattern", "")), re.I | re.S, as_bytes=True)
        if pat:
            script_sigs.append((pat, str(item.get("reason", "Mẫu script nguy hiểm")), _parse_severity(str(item.get("severity", "HIGH")))))

    binary_sigs: List[Tuple[re.Pattern[bytes], str, Severity]] = []
    for item in feed.get("binary_signatures") or []:
        if not isinstance(item, dict):
            continue
        pat = compile_feed_regex(str(item.get("pattern", "")), re.I | re.S, as_bytes=True)
        if pat:
            binary_sigs.append((pat, str(item.get("reason", "Mẫu tệp nhị phân nguy hiểm")), _parse_severity(str(item.get("severity", "HIGH")))))

    parsed = {
        "sha256_iocs": sha256_iocs,
        "filenames": filenames,
        "malicious_paths": malicious_paths,
        "path_basenames": path_basenames,
        "script_sigs": script_sigs,
        "binary_sigs": binary_sigs,
    }
    _FILE_FEED_CACHE = (cache_key, parsed)
    return parsed


def analyze_single_file(file_path: Path) -> Optional[ThreatFinding]:
    """Run static heuristic and threat-feed checks on a single file."""
    try:
        if not file_path.is_file():
            return None
        size = file_path.stat().st_size
        if size == 0 or size > 80 * 1024 * 1024:
            return None

        rules = _get_file_feed_rules()
        name_lower = file_path.name.lower()
        ext = file_path.suffix.lower()
        reasons: List[str] = []
        severity = Severity.INFO

        # 0. Known malicious file path
        for variant in _norm_path_variants(file_path):
            if variant in rules["malicious_paths"]:
                p_desc, p_sev = rules["malicious_paths"][variant]
                reasons.append(p_desc)
                if p_sev.rank > severity.rank:
                    severity = p_sev
                break

        # 1. Known malicious filename
        for fname_map in (KNOWN_MALICIOUS_FILENAMES, rules["filenames"]):
            if name_lower in fname_map:
                desc, sev = fname_map[name_lower]
                if desc not in reasons:
                    reasons.append(desc)
                if sev.rank > severity.rank:
                    severity = sev

        # 2. Content heuristics for scripts & binaries (read up to 4 MB)
        sample = b""
        if ext in SCRIPT_EXTS or ext in BINARY_EXTS:
            try:
                with file_path.open("rb") as f:
                    sample = f.read(4 * 1024 * 1024)
            except OSError:
                sample = b""

            if sample:
                sigs = (
                    SCRIPT_SIGNATURES + rules["script_sigs"]
                    if ext in SCRIPT_EXTS
                    else BINARY_SIGNATURES + rules["binary_sigs"]
                )
                for pat, desc, sev in sigs:
                    if pat.search(sample):
                        if desc not in reasons:
                            reasons.append(desc)
                        if sev.rank > severity.rank:
                            severity = sev

        # 3. SHA-256 IOC lookup (reusing 4 MB in-memory sample when possible)
        precomputed_sha = ""
        sha_iocs = rules["sha256_iocs"]
        if sha_iocs:
            if sample and size <= 4 * 1024 * 1024 and len(sample) == size:
                precomputed_sha = hashlib.sha256(sample).hexdigest()
            elif size <= 16 * 1024 * 1024 and (ext in SCRIPT_EXTS or ext in BINARY_EXTS):
                precomputed_sha = compute_sha256(file_path, max_bytes=16 * 1024 * 1024)
            if precomputed_sha and precomputed_sha.lower() in sha_iocs:
                ioc_name, ioc_sev = sha_iocs[precomputed_sha.lower()]
                reasons.append(f"Khớp mã băm SHA-256 mã độc đã biết: {ioc_name}")
                if ioc_sev.rank > severity.rank:
                    severity = ioc_sev

        if not reasons:
            return None

        sha = precomputed_sha or compute_sha256(file_path)
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
    rules = _get_file_feed_rules()

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
            fname_lower = fname.lower()
            if (
                ext not in SCRIPT_EXTS
                and ext not in BINARY_EXTS
                and fname_lower not in KNOWN_MALICIOUS_FILENAMES
                and fname_lower not in rules["filenames"]
                and fname_lower not in rules["path_basenames"]
            ):
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
    """Scan common malware drop hotspots (SystemHealth, Temp, Desktop, Downloads, AppData)."""
    hotspots = [
        Path(r"C:\Windows\SystemHealth"),
        Path(os.environ.get("TEMP", "")),
        Path(r"C:\Windows\Temp"),
        Path.home() / "Desktop",
        Path.home() / "Downloads",
        Path(r"C:\ProgramData\remcos"),
    ]
    if os.environ.get("APPDATA"):
        hotspots.append(Path(os.environ["APPDATA"]) / r"Microsoft\Windows\Temp")

    all_findings: List[ThreatFinding] = []
    total_scanned = 0
    seen_targets: Set[str] = set()
    for hs in hotspots:
        if cancel_event and cancel_event.is_set():
            break
        if hs.is_dir():
            fs, cnt = scan_path_heuristics(hs, progress_cb=progress_cb, cancel_event=cancel_event, max_files=800)
            for item in fs:
                seen_targets.update(_norm_path_variants(item.target))
            all_findings.extend(fs)
            total_scanned += cnt

    # Explicitly inspect any existing known malicious file paths outside walked hotspots
    for item in load_threat_feed().get("malicious_file_paths") or []:
        if cancel_event and cancel_event.is_set():
            break
        if not isinstance(item, dict) or not item.get("path"):
            continue
        candidate = Path(os.path.expandvars(str(item["path"])))
        if candidate.is_file() and not (_norm_path_variants(candidate) & seen_targets):
            total_scanned += 1
            finding = analyze_single_file(candidate)
            if finding:
                seen_targets.update(_norm_path_variants(finding.target))
                all_findings.append(finding)

    all_findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return all_findings, total_scanned
