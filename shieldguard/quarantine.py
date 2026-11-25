from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Tuple
import uuid
import winreg

import psutil

from .models import QuarantineItem, ThreatCategory, ThreatFinding
from .utils import APP_DATA_DIR, _hidden_startupinfo, compute_sha256, ensure_app_dirs, run_powershell

QUARANTINE_DIR = APP_DATA_DIR / "Quarantine"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"
HISTORY_FILE = APP_DATA_DIR / "action_history.json"
XOR_KEY = 0x5A


def _ensure_quarantine_dir() -> Path:
    ensure_app_dirs()
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    return QUARANTINE_DIR


def _xor_transform_file(src: Path, dst: Path) -> None:
    """XOR-obfuscate file bytes so quarantined malware can never be executed accidentally."""
    with src.open("rb") as fin, dst.open("wb") as fout:
        while True:
            chunk = fin.read(65536)
            if not chunk:
                break
            fout.write(bytes(b ^ XOR_KEY for b in chunk))


def load_quarantine_items() -> List[QuarantineItem]:
    _ensure_quarantine_dir()
    if not MANIFEST_FILE.exists():
        return []
    try:
        raw = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
        return [QuarantineItem.from_dict(x) for x in raw]
    except Exception:
        return []


def _save_quarantine_items(items: List[QuarantineItem]) -> None:
    _ensure_quarantine_dir()
    MANIFEST_FILE.write_text(
        json.dumps([x.to_dict() for x in items], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_history() -> List[Dict[str, Any]]:
    ensure_app_dirs()
    if not HISTORY_FILE.exists():
        return []
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def record_history(action: str, target: str, success: bool, message: str) -> None:
    ensure_app_dirs()
    hist = load_history()
    hist.insert(
        0,
        {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "target": target,
            "success": success,
            "message": message,
        },
    )
    HISTORY_FILE.write_text(json.dumps(hist[:200], indent=2, ensure_ascii=False), encoding="utf-8")


def quarantine_file(file_path: str | Path, threat_title: str = "Malware") -> Tuple[bool, str]:
    """Neutralize and move a malicious file into the Quarantine vault."""
    src = Path(file_path)
    if not src.exists():
        return False, f"Tệp không tồn tại: {src}"
    if not src.is_file():
        return False, "Chỉ hỗ trợ cách ly tệp đơn lẻ (không phải thư mục)."

    _ensure_quarantine_dir()
    item_id = uuid.uuid4().hex[:12]
    sha = compute_sha256(src)
    size = src.stat().st_size
    dst = QUARANTINE_DIR / f"{item_id}.sgq"

    try:
        _xor_transform_file(src, dst)
        # Clear readonly/hidden/system attributes before deleting original
        subprocess.run(
            ["attrib", "-h", "-s", "-r", str(src)],
            capture_output=True,
            startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        src.unlink()
    except PermissionError:
        if dst.exists():
            dst.unlink(missing_ok=True)
        msg = f"Không đủ quyền xóa tệp (cần quyền Administrator hoặc tệp đang chạy): {src}"
        record_history("Quarantine", str(src), False, msg)
        return False, msg
    except Exception as exc:
        if dst.exists():
            dst.unlink(missing_ok=True)
        msg = f"Lỗi khi cách ly: {exc}"
        record_history("Quarantine", str(src), False, msg)
        return False, msg

    items = load_quarantine_items()
    items.insert(
        0,
        QuarantineItem(
            id=item_id,
            original_path=str(src),
            quarantine_path=str(dst),
            threat_title=threat_title,
            sha256=sha,
            quarantined_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            size_bytes=size,
        ),
    )
    _save_quarantine_items(items)
    msg = f"Đã cách ly an toàn tệp vào kho ShieldGuard ({item_id}.sgq)."
    record_history("Quarantine", str(src), True, msg)
    return True, msg


def restore_quarantine_item(item_id: str) -> Tuple[bool, str]:
    """Restore a previously quarantined file back to its original path."""
    items = load_quarantine_items()
    target_item = next((x for x in items if x.id == item_id), None)
    if not target_item:
        return False, "Không tìm thấy mục trong kho cách ly."

    qpath = Path(target_item.quarantine_path)
    orig = Path(target_item.original_path)
    if not qpath.is_file():
        return False, "Tệp cách ly không còn trên ổ đĩa."

    try:
        orig.parent.mkdir(parents=True, exist_ok=True)
        _xor_transform_file(qpath, orig)
        qpath.unlink(missing_ok=True)
        items = [x for x in items if x.id != item_id]
        _save_quarantine_items(items)
        msg = f"Đã khôi phục tệp về: {orig}"
        record_history("Restore", str(orig), True, msg)
        return True, msg
    except Exception as exc:
        msg = f"Lỗi khi khôi phục: {exc}"
        record_history("Restore", str(orig), False, msg)
        return False, msg


def delete_quarantine_item_permanently(item_id: str) -> Tuple[bool, str]:
    """Permanently delete a quarantined file from disk."""
    items = load_quarantine_items()
    target_item = next((x for x in items if x.id == item_id), None)
    if not target_item:
        return False, "Không tìm thấy mục trong kho cách ly."
    try:
        Path(target_item.quarantine_path).unlink(missing_ok=True)
        items = [x for x in items if x.id != item_id]
        _save_quarantine_items(items)
        msg = f"Đã xóa vĩnh viễn tệp cách ly ({target_item.original_path})."
        record_history("Delete Permanent", target_item.original_path, True, msg)
        return True, msg
    except Exception as exc:
        return False, f"Lỗi khi xóa vĩnh viễn: {exc}"


def remediate_finding(finding: ThreatFinding) -> Tuple[bool, str]:
    """Execute 1-click remediation for any ThreatFinding category."""
    cat = finding.category
    d = finding.details

    if cat == ThreatCategory.PROCESS:
        pid = d.get("pid")
        if not pid:
            return False, "Không xác định được PID tiến trình."
        try:
            proc = psutil.Process(int(pid))
            proc.kill()
            proc.wait(timeout=3)
            msg = f"Đã diệt tiến trình PID {pid} ({d.get('name', '')})."
            finding.remediated = True
            record_history("Kill Process", finding.target, True, msg)
            return True, msg
        except psutil.NoSuchProcess:
            finding.remediated = True
            return True, f"Tiến trình PID {pid} đã dừng trước đó."
        except psutil.AccessDenied:
            # Fallback to taskkill /F /T
            p = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                text=True,
                startupinfo=_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if p.returncode == 0:
                finding.remediated = True
                msg = f"Đã diệt cây tiến trình PID {pid}."
                record_history("Kill Process", finding.target, True, msg)
                return True, msg
            msg = "Từ chối truy cập — hãy bấm 'Chạy với quyền Administrator' rồi thử lại."
            record_history("Kill Process", finding.target, False, msg)
            return False, msg
        except Exception as exc:
            return False, f"Lỗi khi diệt tiến trình: {exc}"

    if cat == ThreatCategory.SCHEDULED_TASK:
        tname = str(d.get("task_name", "")).replace("'", "''")
        tpath = str(d.get("task_path", "\\")).replace("'", "''")
        script = (
            f"Disable-ScheduledTask -TaskName '{tname}' -TaskPath '{tpath}' -ErrorAction SilentlyContinue | Out-Null; "
            f"Stop-ScheduledTask -TaskName '{tname}' -TaskPath '{tpath}' -ErrorAction SilentlyContinue | Out-Null; "
            f"Unregister-ScheduledTask -TaskName '{tname}' -TaskPath '{tpath}' -Confirm:$false -ErrorAction Stop"
        )
        rc, _, err = run_powershell(script)
        if rc == 0:
            finding.remediated = True
            msg = f"Đã xóa Scheduled Task {tpath}{tname}."
            record_history("Remove Task", finding.target, True, msg)
            return True, msg
        msg = f"Không thể xóa task (cần quyền Administrator): {err}"
        record_history("Remove Task", finding.target, False, msg)
        return False, msg

    if cat == ThreatCategory.REGISTRY:
        hive_name = str(d.get("hive", "HKCU")).upper()
        subkey = str(d.get("subkey", ""))
        val_name = str(d.get("value_name", ""))
        if hive_name not in ("HKCU", "HKLM"):
            return False, f"Hive Registry không hợp lệ: {hive_name}"

        if d.get("delete_key") is True:
            clean_subkey = subkey.strip("\\/")
            segments = [s for s in clean_subkey.split("\\") if s]
            lower_key = clean_subkey.lower()
            protected_roots = {"software", "system", "microsoft", "windows"}
            protected_suffixes = (
                "\\run",
                "\\runonce",
                "\\winlogon",
                "\\currentversion",
                "\\microsoft",
                "\\windows",
                "\\explorer",
                "\\policies",
                "\\services",
            )
            if len(segments) < 2 or lower_key in protected_roots or lower_key.endswith(protected_suffixes):
                msg = f"Từ chối xóa nhánh Registry được bảo vệ: {hive_name}\\{clean_subkey}"
                record_history("Clean Registry", finding.target, False, msg)
                return False, msg

            p = subprocess.run(
                ["reg.exe", "delete", f"{hive_name}\\{clean_subkey}", "/f"],
                capture_output=True,
                text=True,
                startupinfo=_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            if p.returncode == 0:
                finding.remediated = True
                msg = f"Đã xóa nhánh Registry mã độc: {hive_name}\\{clean_subkey}"
                record_history("Clean Registry", finding.target, True, msg)
                return True, msg
            err_txt = (p.stderr or p.stdout or "").strip()
            msg = f"Không thể xóa nhánh Registry '{hive_name}\\{clean_subkey}': {err_txt}"
            record_history("Clean Registry", finding.target, False, msg)
            return False, msg

        hive = winreg.HKEY_CURRENT_USER if hive_name == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                if val_name.lower() == "shell" and "winlogon" in subkey.lower():
                    winreg.SetValueEx(key, "Shell", 0, winreg.REG_SZ, "explorer.exe")
                    msg = "Đã khôi phục Winlogon Shell về mặc định 'explorer.exe'."
                else:
                    winreg.DeleteValue(key, val_name)
                    msg = f"Đã xóa khóa Registry Startup: {finding.target}"
            finding.remediated = True
            record_history("Clean Registry", finding.target, True, msg)
            return True, msg
        except PermissionError:
            msg = "Cần quyền Administrator để chỉnh sửa khóa HKLM."
            record_history("Clean Registry", finding.target, False, msg)
            return False, msg
        except Exception as exc:
            return False, f"Lỗi Registry: {exc}"

    if cat in (ThreatCategory.FILE, ThreatCategory.STARTUP_FILE):
        fpath = d.get("path") or finding.target
        ok, msg = quarantine_file(fpath, threat_title=finding.title)
        if ok:
            finding.remediated = True
        return ok, msg

    if cat == ThreatCategory.SERVICE:
        sname = str(d.get("service_name") or finding.target)
        p1 = subprocess.run(["sc.exe", "stop", sname], capture_output=True, text=True, startupinfo=_hidden_startupinfo(), creationflags=subprocess.CREATE_NO_WINDOW)
        p2 = subprocess.run(["sc.exe", "delete", sname], capture_output=True, text=True, startupinfo=_hidden_startupinfo(), creationflags=subprocess.CREATE_NO_WINDOW)
        if p2.returncode == 0:
            finding.remediated = True
            msg = f"Đã dừng và xóa service '{sname}'."
            record_history("Remove Service", sname, True, msg)
            return True, msg
        msg = f"Không thể xóa service '{sname}' (cần quyền Administrator): {p2.stdout.strip() or p1.stdout.strip()}"
        record_history("Remove Service", sname, False, msg)
        return False, msg

    if cat == ThreatCategory.WMI:
        wname = str(d.get("wmi_name") or finding.target).replace("'", "''")
        script = (
            f"Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer | "
            f"Where-Object {{ $_.Name -eq '{wname}' }} | Remove-CimInstance -ErrorAction Stop"
        )
        rc, _, err = run_powershell(script)
        if rc == 0:
            finding.remediated = True
            msg = f"Đã xóa WMI Event Consumer '{wname}'."
            record_history("Remove WMI", wname, True, msg)
            return True, msg
        return False, f"Không thể xóa WMI (cần quyền Administrator): {err}"

    if cat == ThreatCategory.DEFENDER_EXCLUSION:
        atype = d.get("action_type", "")
        val = str(d.get("value", "")).replace("'", "''")
        if atype == "enable_realtime":
            script = "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop"
        elif atype == "remove_path":
            script = f"Remove-MpPreference -ExclusionPath '{val}' -ErrorAction Stop"
        elif atype == "remove_process":
            script = f"Remove-MpPreference -ExclusionProcess '{val}' -ErrorAction Stop"
        elif atype == "remove_extension":
            script = f"Remove-MpPreference -ExclusionExtension '{val}' -ErrorAction Stop"
        else:
            return False, "Hành động Defender không xác định."

        rc, _, err = run_powershell(script)
        if rc == 0:
            finding.remediated = True
            msg = f"Đã xử lý cấu hình Windows Defender: {finding.target}"
            record_history("Defender Fix", finding.target, True, msg)
            return True, msg
        msg = f"Không thể thay đổi Windows Defender (cần quyền Administrator): {err}"
        record_history("Defender Fix", finding.target, False, msg)
        return False, msg

    return False, "Loại mối đe dọa chưa hỗ trợ xử lý tự động."
