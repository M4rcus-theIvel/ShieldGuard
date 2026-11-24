from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from .models import Severity, ThreatCategory, ThreatFinding
from .utils import is_admin, run_powershell_json

DANGEROUS_EXCLUSION_PATHS_RE = re.compile(
    r"(^c:\\?$|^c:\\windows\\?$|^c:\\windows\\systemhealth|^c:\\users\\?$|\\appdata\\|\\temp\\|\\desktop|\\downloads|xmrig|batteryhub|miner)",
    re.I,
)

BENIGN_DEV_EXCLUSION_RE = re.compile(
    r"(jetbrains|intellij|pycharm|webstorm|androidstudio|visual studio|ideaprojects|\.gradle|\.m2|node_modules)",
    re.I,
)

DANGEROUS_EXCLUSION_PROCS_RE = re.compile(
    r"(xmrig|python|powershell|cmd\.exe|conhost|wscript|cscript|sysmon|normalizer|miner)",
    re.I,
)

DANGEROUS_EXCLUSION_EXTS = {".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".py", ".scr", "exe", "dll", "ps1", "py"}


def scan_defender() -> Tuple[List[ThreatFinding], Dict[str, Any]]:
    """Audit Windows Defender real-time protection status and exclusions."""
    findings: List[ThreatFinding] = []
    status: Dict[str, Any] = {
        "is_admin": is_admin(),
        "realtime_enabled": None,
        "exclusion_paths": [],
        "exclusion_processes": [],
        "exclusion_extensions": [],
        "error": "",
    }

    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$mp = Get-MpPreference
$st = Get-MpComputerStatus
[PSCustomObject]@{
    DisableRealtimeMonitoring = $mp.DisableRealtimeMonitoring
    RealTimeProtectionEnabled = $st.RealTimeProtectionEnabled
    ExclusionPath             = @($mp.ExclusionPath)
    ExclusionProcess          = @($mp.ExclusionProcess)
    ExclusionExtension        = @($mp.ExclusionExtension)
} | ConvertTo-Json -Depth 3 -Compress
"""
    data = run_powershell_json(ps_script, timeout=20)
    if not isinstance(data, dict):
        status["error"] = "Không thể truy vấn Windows Defender (có thể bị tắt hoặc thiếu quyền)."
        return findings, status

    rt_enabled = data.get("RealTimeProtectionEnabled")
    if rt_enabled is None and data.get("DisableRealtimeMonitoring") is not None:
        rt_enabled = not bool(data.get("DisableRealtimeMonitoring"))
    status["realtime_enabled"] = rt_enabled

    if rt_enabled is False:
        findings.append(
            ThreatFinding(
                title="Windows Defender Real-Time Protection is DISABLED",
                category=ThreatCategory.DEFENDER_EXCLUSION,
                severity=Severity.CRITICAL,
                target="RealTimeProtection",
                reason="Windows Defender real-time protection is turned off.",
                details={"action_type": "enable_realtime"},
                title_key="f_def_rt_off_t",
                reason_key="f_def_rt_off_r",
            )
        )

    def _clean_list(raw: Any) -> List[str]:
        if not raw:
            return []
        if isinstance(raw, str):
            raw = [raw]
        return [
            str(x).strip()
            for x in raw
            if x and "Must be an administrator" not in str(x)
        ]

    excl_paths = _clean_list(data.get("ExclusionPath"))
    excl_procs = _clean_list(data.get("ExclusionProcess"))
    excl_exts = _clean_list(data.get("ExclusionExtension"))

    status["exclusion_paths"] = excl_paths
    status["exclusion_processes"] = excl_procs
    status["exclusion_extensions"] = excl_exts

    for ep in excl_paths:
        is_benign_dev = bool(BENIGN_DEV_EXCLUSION_RE.search(ep))
        is_danger = bool(DANGEROUS_EXCLUSION_PATHS_RE.search(ep)) and not is_benign_dev
        if is_danger:
            sev = Severity.CRITICAL
            rkey = "f_def_path_danger"
        elif is_benign_dev:
            sev = Severity.LOW
            rkey = "f_def_path_dev"
        else:
            sev = Severity.MEDIUM
            rkey = "f_def_path_med"
        findings.append(
            ThreatFinding(
                title=f"Defender Folder Exclusion: {ep}",
                category=ThreatCategory.DEFENDER_EXCLUSION,
                severity=sev,
                target=ep,
                reason="",
                details={"action_type": "remove_path", "value": ep},
                title_key="f_def_path_t",
                title_args={"val": ep},
                reason_key=rkey,
            )
        )

    for eproc in excl_procs:
        is_danger = bool(DANGEROUS_EXCLUSION_PROCS_RE.search(eproc))
        findings.append(
            ThreatFinding(
                title=f"Defender Process Exclusion: {eproc}",
                category=ThreatCategory.DEFENDER_EXCLUSION,
                severity=Severity.HIGH if is_danger else Severity.MEDIUM,
                target=eproc,
                reason="",
                details={"action_type": "remove_process", "value": eproc},
                title_key="f_def_proc_t",
                title_args={"val": eproc},
                reason_key="f_def_proc_danger" if is_danger else "f_def_proc_med",
            )
        )

    for eext in excl_exts:
        is_danger = eext.lower().strip() in DANGEROUS_EXCLUSION_EXTS
        findings.append(
            ThreatFinding(
                title=f"Defender Extension Exclusion: {eext}",
                category=ThreatCategory.DEFENDER_EXCLUSION,
                severity=Severity.HIGH if is_danger else Severity.LOW,
                target=eext,
                reason="",
                details={"action_type": "remove_extension", "value": eext},
                title_key="f_def_ext_t",
                title_args={"val": eext},
                reason_key="f_def_ext_danger" if is_danger else "f_def_ext_low",
            )
        )

    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings, status
