from __future__ import annotations

import os
from pathlib import Path
import re
from typing import Any, Dict, List, Set, Tuple
import winreg

from .models import Severity, ThreatCategory, ThreatFinding
from .utils import compile_feed_regex, load_threat_feed, run_powershell_json

_SVC_NAME_RE = re.compile(r"WinRing0|xmrig|SysCheck|SysMon", re.I)
_SVC_PATH_RE = re.compile(r"SystemHealth|xmrig|WinRing0|\\Temp\\|\\Users\\Public\\|powershell.*-enc", re.I)


def _parse_pers_severity(val: str, default: Severity = Severity.HIGH) -> Severity:
    try:
        return Severity(str(val).upper())
    except ValueError:
        return default


def _get_persistence_feed() -> Tuple[List[Tuple[re.Pattern[str], str, Severity]], List[Dict[str, Any]]]:
    feed = load_threat_feed()
    cmd_patterns: List[Tuple[re.Pattern[str], str, Severity]] = []
    for item in feed.get("cmd_patterns") or []:
        if not isinstance(item, dict):
            continue
        pat = compile_feed_regex(str(item.get("pattern", "")), re.I | re.S)
        if pat:
            cmd_patterns.append((pat, str(item.get("reason", "")), _parse_pers_severity(str(item.get("severity", "HIGH")))))
    reg_keys = [rk for rk in (feed.get("registry_keys") or []) if isinstance(rk, dict)]
    return cmd_patterns, reg_keys

SUSPICIOUS_ACTION_RE = re.compile(
    r"(systemhealth|sysmon\.py|xmrig|conhost\.exe\s+--headless|powershell.*(-w\s+hidden|-windowstyle\s+hidden|-enc|-encodedcommand)|"
    r"mshta|wscript|cscript|stratum|battery-hub\.net|\\windows\\temp\\|\\appdata\\local\\temp\\)",
    re.I,
)

KNOWN_SAFE_TASK_PREFIXES = (
    "\\Microsoft\\Windows\\",
    "\\Microsoft\\Office\\",
    "\\Microsoft\\XblGameSave\\",
    "\\SoftLanding\\",
)

KNOWN_SAFE_TASK_NAMES = (
    "OneDrive",
    "NVIDIA",
    "NvDriverUpdateCheck",
    "Nahimic",
    "Opera",
    "Vivaldi",
    "ZoomUpdateTask",
    "GoogleUpdate",
    "EdgeUpdate",
    "Adobe",
    "Dropbox",
    "Messenger-WSP-Helper",
    "UninstallSMB1ClientTask",
    "UninstallSMB1ServerTask",
)


def _scan_scheduled_tasks() -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    cmd_patterns, _ = _get_persistence_feed()
    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
Get-ScheduledTask | ForEach-Object {
    $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' | '
    if ($act) {
        $out += [PSCustomObject]@{
            TaskName = $_.TaskName
            TaskPath = $_.TaskPath
            State    = "$($_.State)"
            RunLevel = "$($_.Principal.RunLevel)"
            Action   = $act
        }
    }
}
$out | ConvertTo-Json -Depth 3 -Compress
"""
    data = run_powershell_json(ps_script, timeout=35)
    if not data:
        return findings
    if isinstance(data, dict):
        data = [data]

    for item in data:
        tname = str(item.get("TaskName") or "")
        tpath = str(item.get("TaskPath") or "\\")
        state = str(item.get("State") or "")
        run_level = str(item.get("RunLevel") or "")
        action = str(item.get("Action") or "")

        if state == "Disabled":
            continue

        is_ms = any(tpath.startswith(pref) for pref in KNOWN_SAFE_TASK_PREFIXES)
        is_known_safe = any(tname.startswith(sn) for sn in KNOWN_SAFE_TASK_NAMES)

        # Skip known built-in Windows SMB1 cleanup tasks that legitimately use hidden PowerShell
        if is_ms and is_known_safe:
            continue

        action_expanded = os.path.expandvars(action).lower()
        base_match = bool(SUSPICIOUS_ACTION_RE.search(action))
        feed_reasons: List[str] = []
        max_sev = Severity.CRITICAL if re.search(r"systemhealth|sysmon|xmrig|conhost.*--headless", action, re.I) else Severity.HIGH

        for pat, desc, p_sev in cmd_patterns:
            if pat.search(action):
                if desc and desc not in feed_reasons:
                    feed_reasons.append(desc)
                if p_sev.rank > max_sev.rank:
                    max_sev = p_sev

        if feed_reasons:
            findings.append(
                ThreatFinding(
                    title=f"Scheduled Task: {tpath}{tname}",
                    category=ThreatCategory.SCHEDULED_TASK,
                    severity=max_sev,
                    target=f"{tpath}{tname}",
                    reason=f"{'; '.join(feed_reasons)} | {action}",
                    details={"task_name": tname, "task_path": tpath, "action": action, "run_level": run_level},
                    title_key="f_per_task_mal_t",
                    title_args={"task": f"{tpath}{tname}"},
                )
            )
        elif base_match:
            findings.append(
                ThreatFinding(
                    title=f"Scheduled Task: {tpath}{tname}",
                    category=ThreatCategory.SCHEDULED_TASK,
                    severity=max_sev,
                    target=f"{tpath}{tname}",
                    reason=action,
                    details={"task_name": tname, "task_path": tpath, "action": action, "run_level": run_level},
                    title_key="f_per_task_mal_t",
                    title_args={"task": f"{tpath}{tname}"},
                    reason_key="f_per_task_mal_r",
                    reason_args={"level": run_level, "action": action},
                )
            )
        elif not is_ms and not is_known_safe and run_level == "Highest":
            # Flag unknown root tasks running with Highest privileges pointing to non-Program Files
            if (
                "program files" not in action_expanded
                and "windows\\system32" not in action_expanded
                and "windows\\syswow64" not in action_expanded
            ):
                findings.append(
                    ThreatFinding(
                        title=f"Scheduled Task: {tpath}{tname}",
                        category=ThreatCategory.SCHEDULED_TASK,
                        severity=Severity.MEDIUM,
                        target=f"{tpath}{tname}",
                        reason=action,
                        details={"task_name": tname, "task_path": tpath, "action": action, "run_level": run_level},
                        title_key="f_per_task_hi_t",
                        title_args={"task": f"{tpath}{tname}"},
                        reason_key="f_per_task_hi_r",
                        reason_args={"action": action},
                    )
                )

    return findings


def _scan_registry_startup() -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    cmd_patterns, feed_reg_keys = _get_persistence_feed()
    seen_reg: Set[Tuple[str, str, str]] = set()

    # Check known malware-specific Registry keys & values from threat feed
    for rk in feed_reg_keys:
        hive_name = str(rk.get("hive") or "").upper()
        if hive_name not in ("HKCU", "HKLM"):
            continue
        hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        clean_subkey = str(rk.get("subkey") or "").strip("\\/")
        val_name = str(rk.get("value_name") or "")
        if not clean_subkey:
            continue
        reason = str(rk.get("reason") or "Khóa Registry mã độc đã biết")
        sev = _parse_pers_severity(str(rk.get("severity", "HIGH")))
        try:
            with winreg.OpenKey(hive, clean_subkey, 0, winreg.KEY_READ) as key:
                if val_name:
                    val_data, _ = winreg.QueryValueEx(key, val_name)
                    dedup_key = (hive_name, clean_subkey.lower(), val_name.lower())
                    if dedup_key not in seen_reg:
                        seen_reg.add(dedup_key)
                        findings.append(
                            ThreatFinding(
                                title=f"Registry mã độc phát hiện: {val_name}",
                                category=ThreatCategory.REGISTRY,
                                severity=sev,
                                target=f"{hive_name}\\{clean_subkey}\\{val_name}",
                                reason=f"{reason} (Giá trị: {val_data})",
                                details={"hive": hive_name, "subkey": clean_subkey, "value_name": val_name, "value_data": str(val_data)},
                            )
                        )
                else:
                    dedup_key = (hive_name, clean_subkey.lower(), "")
                    if dedup_key not in seen_reg:
                        seen_reg.add(dedup_key)
                        findings.append(
                            ThreatFinding(
                                title=f"Nhánh Registry mã độc: {hive_name}\\{clean_subkey}",
                                category=ThreatCategory.REGISTRY,
                                severity=sev,
                                target=f"{hive_name}\\{clean_subkey}",
                                reason=reason,
                                details={"hive": hive_name, "subkey": clean_subkey, "value_name": "", "delete_key": True},
                            )
                        )
        except OSError:
            continue

    locations = [
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, hive_name, subkey in locations:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, idx)
                        idx += 1
                    except OSError:
                        break
                    dedup_key = (hive_name, subkey.strip("\\").lower(), str(val_name).lower())
                    if dedup_key in seen_reg:
                        continue
                    val_str = str(val_data)
                    matched_reasons: List[str] = []
                    sev = Severity.HIGH
                    if SUSPICIOUS_ACTION_RE.search(val_str):
                        matched_reasons.append(f"Giá trị khởi động chứa lệnh nghi ngờ: {val_str}")
                    for pat, desc, p_sev in cmd_patterns:
                        if pat.search(val_str):
                            if desc and desc not in matched_reasons:
                                matched_reasons.append(desc)
                            if p_sev.rank > sev.rank:
                                sev = p_sev
                    if matched_reasons:
                        seen_reg.add(dedup_key)
                        findings.append(
                            ThreatFinding(
                                title=f"Registry Startup nghi ngờ: {val_name}",
                                category=ThreatCategory.REGISTRY,
                                severity=sev,
                                target=f"{hive_name}\\{subkey}\\{val_name}",
                                reason="; ".join(matched_reasons) + (f" ({val_str})" if len(matched_reasons) == 1 and val_str not in matched_reasons[0] else ""),
                                details={"hive": hive_name, "subkey": subkey, "value_name": val_name, "value_data": val_str},
                            )
                        )
        except OSError:
            continue

    # Check Winlogon Shell & Userinit tampering
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0, winreg.KEY_READ) as key:
            shell_val, _ = winreg.QueryValueEx(key, "Shell")
            if str(shell_val).strip().lower() != "explorer.exe":
                findings.append(
                    ThreatFinding(
                        title="Winlogon Shell bị thay đổi",
                        category=ThreatCategory.REGISTRY,
                        severity=Severity.CRITICAL,
                        target=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
                        reason=f"Giá trị chuẩn là 'explorer.exe' nhưng hiện tại là: {shell_val}",
                        details={"hive": "HKLM", "subkey": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "Shell", "value_data": str(shell_val)},
                    )
                )
    except OSError:
        pass

    return findings


def _scan_startup_folders() -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    folders = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    suspicious_exts = {".bat", ".cmd", ".vbs", ".vbe", ".ps1", ".js", ".jse", ".hta", ".scr", ".py", ".wsf", ".wsh"}
    for folder in folders:
        if not folder.is_dir():
            continue
        try:
            for item in folder.iterdir():
                if item.name.lower() == "desktop.ini":
                    continue
                ext = item.suffix.lower()
                if ext in suspicious_exts or SUSPICIOUS_ACTION_RE.search(item.name):
                    findings.append(
                        ThreatFinding(
                            title=f"File Startup nghi ngờ: {item.name}",
                            category=ThreatCategory.STARTUP_FILE,
                            severity=Severity.HIGH,
                            target=str(item),
                            reason=f"Script hoặc tệp thực thi đáng ngờ nằm trong thư mục Startup ({ext})",
                            details={"path": str(item)},
                        )
                    )
        except OSError:
            continue
    return findings


def _scan_services_and_wmi() -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    cmd_patterns, _ = _get_persistence_feed()
    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$svcs = Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName

$wmi = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate

[PSCustomObject]@{ Services = @($svcs); Wmi = @($wmi) } | ConvertTo-Json -Depth 3 -Compress
"""
    data = run_powershell_json(ps_script, timeout=25)
    if not isinstance(data, dict):
        return findings

    for svc in data.get("Services") or []:
        if not isinstance(svc, dict) or not svc.get("Name"):
            continue
        sname = str(svc["Name"])
        spath = str(svc.get("PathName") or "")
        base_hit = bool(_SVC_NAME_RE.search(sname) or _SVC_PATH_RE.search(spath))
        feed_reasons: List[str] = []
        sev = Severity.CRITICAL if "winring0" in sname.lower() or "xmrig" in spath.lower() else Severity.HIGH
        for pat, desc, p_sev in cmd_patterns:
            if pat.search(spath):
                if desc and desc not in feed_reasons:
                    feed_reasons.append(desc)
                if p_sev.rank > sev.rank:
                    sev = p_sev
        if not base_hit and not feed_reasons:
            continue
        reason_text = f"Trạng thái: {svc.get('State')} | Đường dẫn: {spath}"
        if feed_reasons:
            reason_text = f"{'; '.join(feed_reasons)} | {reason_text}"
        findings.append(
            ThreatFinding(
                title=f"Service/Driver nghi ngờ: {sname}",
                category=ThreatCategory.SERVICE,
                severity=sev,
                target=sname,
                reason=reason_text,
                details={"service_name": sname, "path": spath, "state": svc.get("State")},
            )
        )

    for cons in data.get("Wmi") or []:
        if not isinstance(cons, dict) or not cons.get("Name"):
            continue
        cname = str(cons["Name"])
        cmd = str(cons.get("CommandLineTemplate") or "")
        feed_reasons = [desc for pat, desc, _ in cmd_patterns if desc and pat.search(cmd)]
        extra = f" ({'; '.join(feed_reasons)})" if feed_reasons else ""
        findings.append(
            ThreatFinding(
                title=f"WMI Persistence phát hiện: {cname}",
                category=ThreatCategory.WMI,
                severity=Severity.CRITICAL,
                target=cname,
                reason=f"WMI CommandLineEventConsumer chạy ngầm{extra}: {cmd}",
                details={"wmi_name": cname, "cmdline": cmd},
            )
        )

    return findings


def scan_persistence() -> List[ThreatFinding]:
    """Run all persistence checks: Scheduled Tasks, Registry Run, Startup folders, Services, WMI."""
    findings: List[ThreatFinding] = []
    findings.extend(_scan_scheduled_tasks())
    findings.extend(_scan_registry_startup())
    findings.extend(_scan_startup_folders())
    findings.extend(_scan_services_and_wmi())
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings
