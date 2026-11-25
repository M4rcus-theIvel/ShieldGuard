from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from .models import Severity, ThreatCategory, ThreatFinding
from .utils import _hidden_startupinfo, compile_feed_regex, compute_sha256, load_threat_feed

KNOWN_MINER_NAMES: Set[str] = {
    "xmrig.exe",
    "xmrig-cuda.exe",
    "phoenixminer.exe",
    "lolminer.exe",
    "gminer.exe",
    "t-rex.exe",
    "nbminer.exe",
    "bzminer.exe",
    "srbminer-multi.exe",
    "rigel.exe",
    "teamredminer.exe",
    "ethminer.exe",
    "ccminer.exe",
    "cgminer.exe",
    "bfgminer.exe",
    "cpuminer.exe",
    "nanominer.exe",
    "onezerominer.exe",
    "wildrig.exe",
    "excavator.exe",
    "minerd.exe",
}

MINING_POOL_PORTS: Set[int] = {
    3333,
    4444,
    5555,
    7777,
    8881,
    8888,
    9999,
    14433,
    14444,
    20536,
    45700,
}

SUSPICIOUS_CMD_PATTERNS: List[Tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"stratum\+tcp://|stratum\+ssl://", re.I), "Kết nối giao thức đào coin Stratum", Severity.CRITICAL),
    (re.compile(r"--donate-level|--algo\s+(rx/|kawpow|ethash|autolykos|randomx)", re.I), "Tham số dòng lệnh đặc trưng của phần mềm đào coin", Severity.CRITICAL),
    (re.compile(r"\\windows\\systemhealth\\", re.I), "Chạy từ thư mục giả mạo C:\\Windows\\SystemHealth", Severity.CRITICAL),
    (re.compile(r"sysmon\.py", re.I), "Chạy script giám sát ẩn SysMon.py (mẫu mã độc ẩn Task Manager)", Severity.CRITICAL),
    (re.compile(r"conhost\.exe.*--headless", re.I), "Ẩn cửa sổ console bằng conhost --headless", Severity.HIGH),
    (re.compile(r"powershell.*(-w\s+hidden|-windowstyle\s+hidden).*(iex|downloadstring|-enc|-encodedcommand)", re.I), "PowerShell chạy ẩn thực thi payload từ xa/mã hóa", Severity.CRITICAL),
]

SUSPICIOUS_PATH_REGEX = re.compile(
    r"(^c:\\windows\\systemhealth\\|^c:\\windows\\temp\\|\\appdata\\local\\temp\\|\\users\\public\\)",
    re.I,
)

# Legitimate processes that commonly live in AppData or use GPU/CPU heavily
SAFE_PROCESS_HINTS = (
    "antigravity.exe",
    "code.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "discord.exe",
    "opera.exe",
    "vivaldi.exe",
    "onedrive.exe",
    "spotify.exe",
    "riot client.exe",
    "riotclientservices.exe",
    "steam.exe",
    "epicgameslauncher.exe",
    "nvidia",
    "explorer.exe",
    "dwm.exe",
    "svchost.exe",
    "searchhost.exe",
    "msedgewebview2.exe",
)


def query_nvidia_gpu_status() -> Dict[str, Any]:
    """Query NVIDIA GPU usage and running GPU processes via nvidia-smi without triggering Task Manager evasion."""
    result: Dict[str, Any] = {"available": False, "gpu_name": "", "util_pct": 0, "mem_used_mb": 0, "mem_total_mb": 0, "temp_c": 0, "processes": []}
    try:
        p = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if p.returncode == 0 and p.stdout.strip():
            parts = [x.strip() for x in p.stdout.strip().splitlines()[0].split(",")]
            if len(parts) >= 5:
                result["available"] = True
                result["gpu_name"] = parts[0]
                result["util_pct"] = int(float(parts[1])) if parts[1].replace(".", "", 1).isdigit() else 0
                result["mem_used_mb"] = int(float(parts[2])) if parts[2].replace(".", "", 1).isdigit() else 0
                result["mem_total_mb"] = int(float(parts[3])) if parts[3].replace(".", "", 1).isdigit() else 0
                result["temp_c"] = int(float(parts[4])) if parts[4].replace(".", "", 1).isdigit() else 0

        p2 = subprocess.run(
            ["nvidia-smi", "--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if p2.returncode == 0 and p2.stdout.strip():
            for line in p2.stdout.strip().splitlines():
                cols = [x.strip() for x in line.split(",")]
                if len(cols) >= 3 and cols[0].isdigit():
                    result["processes"].append(
                        {
                            "pid": int(cols[0]),
                            "name": cols[1],
                            "mem_mb": int(float(cols[2])) if cols[2].replace(".", "", 1).isdigit() else 0,
                        }
                    )
    except Exception:
        pass
    return result


def _is_public_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def _is_trusted_install_dir(exe: str) -> bool:
    norm = exe.replace("/", "\\").lower()
    return norm.startswith(
        (
            "c:\\windows\\system32\\",
            "c:\\windows\\syswow64\\",
            "c:\\program files\\",
            "c:\\program files (x86)\\",
        )
    )


def _parse_proc_severity(val: str, default: Severity = Severity.HIGH) -> Severity:
    try:
        return Severity(str(val).upper())
    except ValueError:
        return default


def scan_processes() -> Tuple[List[ThreatFinding], Dict[str, Any]]:
    """Scan all running processes for crypto-miners, stealth watchdogs, C2 connections, and threat-feed IOCs."""
    findings: List[ThreatFinding] = []
    seen_pids: Set[int] = set()
    my_pid = os.getpid()

    feed = load_threat_feed()
    sha256_iocs: Dict[str, Tuple[str, Severity]] = {
        str(k).lower(): (
            str(v.get("name") or "Known Malware"),
            _parse_proc_severity(str(v.get("severity", "CRITICAL")), Severity.CRITICAL),
        )
        for k, v in (feed.get("sha256_iocs") or {}).items()
        if isinstance(v, dict) and k
    }
    c2_ips: Dict[str, Tuple[str, Severity]] = {
        str(k): (
            str(v.get("family") or "Malware C2"),
            _parse_proc_severity(str(v.get("severity", "CRITICAL")), Severity.CRITICAL),
        )
        for k, v in (feed.get("c2_ips") or {}).items()
        if isinstance(v, dict) and k
    }
    c2_ports: Dict[int, Tuple[str, Severity]] = {}
    for k, v in (feed.get("c2_ports") or {}).items():
        if isinstance(v, dict) and str(k).isdigit():
            c2_ports[int(k)] = (
                str(v.get("family") or "Suspicious RAT"),
                _parse_proc_severity(str(v.get("severity", "HIGH")), Severity.HIGH),
            )
    feed_cmd_patterns: List[Tuple[re.Pattern[str], str, Severity]] = []
    for item in feed.get("cmd_patterns") or []:
        if not isinstance(item, dict):
            continue
        pat = compile_feed_regex(str(item.get("pattern", "")), re.I | re.S)
        if pat:
            feed_cmd_patterns.append((pat, str(item.get("reason", "")), _parse_proc_severity(str(item.get("severity", "HIGH")))))

    exe_sha_cache: Dict[str, str] = {}

    gpu_info = query_nvidia_gpu_status()
    gpu_compute_pids: Dict[int, Dict[str, Any]] = {p["pid"]: p for p in gpu_info.get("processes", [])}

    # Build connection map by PID
    conn_by_pid: Dict[int, List[Tuple[str, int]]] = {}
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.pid and c.raddr and c.status == psutil.CONN_ESTABLISHED:
                conn_by_pid.setdefault(c.pid, []).append((c.raddr.ip, c.raddr.port))
    except Exception:
        pass

    total_scanned = 0
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "cpu_percent"]):
        total_scanned += 1
        try:
            info = proc.info
            pid = info["pid"]
            if pid in (0, 4, my_pid):
                continue

            name = (info.get("name") or "").strip()
            name_lower = name.lower()
            exe = (info.get("exe") or "").strip()
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list) if isinstance(cmdline_list, list) else str(cmdline_list)

            is_suspicious_dir = bool(exe and SUSPICIOUS_PATH_REGEX.search(exe))
            is_safe_hint = any(h in name_lower for h in SAFE_PROCESS_HINTS) and not is_suspicious_dir
            in_trusted_dir = bool(exe and _is_trusted_install_dir(exe))

            reasons: List[str] = []
            severity = Severity.INFO

            # 1. Known miner executable name
            if name_lower in KNOWN_MINER_NAMES or "xmrig" in name_lower or "miner" in name_lower:
                if "antigravity" not in name_lower:
                    reasons.append(f"Tên tiến trình trùng phần mềm đào coin ({name})")
                    severity = Severity.CRITICAL

            # 2. Suspicious command line patterns (built-in + threat feed)
            for pat, desc, pat_sev in SUSPICIOUS_CMD_PATTERNS + feed_cmd_patterns:
                if pat.search(cmdline) or pat.search(exe):
                    if desc not in reasons:
                        reasons.append(desc)
                    if pat_sev.rank > severity.rank:
                        severity = pat_sev

            # 3. Running from suspicious directories (especially python/exe/cmd in C:\Windows\SystemHealth or Temp)
            if is_suspicious_dir and not is_safe_hint:
                reasons.append(f"Chạy từ thư mục nguy hiểm: {exe}")
                if Severity.HIGH.rank > severity.rank:
                    severity = Severity.HIGH

            # 3b. SHA-256 IOC check for executables outside trusted OS/Program Files dirs
            if exe and sha256_iocs and not is_safe_hint and not in_trusted_dir:
                exe_key = exe.lower()
                if exe_key not in exe_sha_cache:
                    exe_sha_cache[exe_key] = compute_sha256(exe, max_bytes=50 * 1024 * 1024)
                exe_sha = exe_sha_cache[exe_key]
                if exe_sha and exe_sha.lower() in sha256_iocs:
                    ioc_name, ioc_sev = sha256_iocs[exe_sha.lower()]
                    reasons.append(f"Khớp mã băm SHA-256 mã độc đã biết: {ioc_name}")
                    if ioc_sev.rank > severity.rank:
                        severity = ioc_sev

            # 4. Active connection to mining pools, known C2 IPs, or suspicious RAT C2 ports
            remote_conns = conn_by_pid.get(pid, [])
            for rip, rport in remote_conns:
                if not _is_public_ip(rip):
                    continue
                if rport in MINING_POOL_PORTS:
                    reasons.append(f"Kết nối mạng tới cổng đào coin phổ biến ({rip}:{rport})")
                    if Severity.CRITICAL.rank > severity.rank:
                        severity = Severity.CRITICAL
                if rip in c2_ips:
                    family, c2_sev = c2_ips[rip]
                    reasons.append(f"Kết nối mạng tới máy chủ điều khiển mã độc C2 ({rip}:{rport} — {family})")
                    if c2_sev.rank > severity.rank:
                        severity = c2_sev
                elif rport in c2_ports and not is_safe_hint and not in_trusted_dir:
                    family, port_sev = c2_ports[rport]
                    reasons.append(f"Kết nối mạng tới cổng điều khiển RAT nghi ngờ ({rip}:{rport} — {family})")
                    if port_sev.rank > severity.rank:
                        severity = port_sev

            # 5. GPU compute process that is not on safe list and lives in suspicious path
            if pid in gpu_compute_pids and not is_safe_hint:
                gmem = gpu_compute_pids[pid]["mem_mb"]
                if gmem >= 512 and (not exe or "program files" not in exe.lower()):
                    reasons.append(f"Đang chiếm dụng GPU Compute ({gmem} MB VRAM) từ vị trí bất thường")
                    if Severity.HIGH.rank > severity.rank:
                        severity = Severity.HIGH

            if reasons and pid not in seen_pids:
                seen_pids.add(pid)
                findings.append(
                    ThreatFinding(
                        title=f"Tiến trình nghi ngờ: {name} (PID {pid})",
                        category=ThreatCategory.PROCESS,
                        severity=severity,
                        target=exe or name,
                        reason="; ".join(reasons),
                        details={
                            "pid": pid,
                            "ppid": info.get("ppid"),
                            "name": name,
                            "exe": exe,
                            "cmdline": cmdline[:500],
                            "connections": [f"{ip}:{pt}" for ip, pt in remote_conns[:5]],
                        },
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    meta = {
        "total_processes": total_scanned,
        "gpu": gpu_info,
    }
    return findings, meta
