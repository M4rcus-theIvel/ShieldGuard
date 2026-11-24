from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple


APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "ShieldGuard"
CONFIG_FILE = APP_DATA_DIR / "config.json"


def ensure_app_dirs() -> Path:
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return APP_DATA_DIR


def load_config() -> Dict[str, Any]:
    ensure_app_dirs()
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_app_dirs()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Relaunch the current Python script or frozen exe with UAC elevation."""
    try:
        if getattr(sys, "frozen", False):
            exe = sys.executable
            params = " ".join(f'"{a}"' for a in sys.argv[1:])
        else:
            exe = sys.executable
            script = os.path.abspath(sys.argv[0])
            rest = " ".join(f'"{a}"' for a in sys.argv[1:])
            params = f'"{script}" {rest}'.strip()
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return ret > 32
    except Exception:
        return False


def _hidden_startupinfo() -> subprocess.STARTUPINFO:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


def run_powershell(script: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Run a PowerShell command cleanly without popping up a console window."""
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            startupinfo=_hidden_startupinfo(),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as exc:
        return -1, "", str(exc)


def run_powershell_json(script: str, timeout: int = 30) -> Any:
    """Run a PowerShell command that outputs JSON and parse it safely."""
    rc, out, _ = run_powershell(script, timeout=timeout)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Try finding the JSON block if warnings were printed before it
        for ch_open, ch_close in (("[", "]"), ("{", "}")):
            idx = out.find(ch_open)
            ridx = out.rfind(ch_close)
            if idx != -1 and ridx != -1 and ridx > idx:
                try:
                    return json.loads(out[idx : ridx + 1])
                except json.JSONDecodeError:
                    pass
        return None


def compute_sha256(file_path: str | Path, max_bytes: int = 100 * 1024 * 1024) -> str:
    """Compute SHA-256 of a file (up to max_bytes to avoid hanging on huge files)."""
    h = hashlib.sha256()
    path = Path(file_path)
    try:
        if not path.is_file():
            return ""
        if path.stat().st_size > max_bytes:
            return ""
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def format_bytes(num: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0  # type: ignore[assignment]
    return f"{num:.1f} TB"


def normalize_path(p: str) -> str:
    if not p:
        return ""
    return os.path.expandvars(p.strip().strip('"').strip("'"))
