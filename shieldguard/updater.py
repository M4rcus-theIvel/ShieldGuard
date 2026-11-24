from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, Tuple

import requests

from . import __github_repo__, __version__, __winget_id__
from .utils import _hidden_startupinfo


def _parse_version(ver: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", ver)
    return tuple(int(n) for n in nums) if nums else (0,)


def is_newer_version(latest: str, current: str = __version__) -> bool:
    return _parse_version(latest) > _parse_version(current)


def check_github_update(repo: str = __github_repo__, timeout: int = 10) -> Dict[str, Any]:
    """Query GitHub Releases API to check whether a newer ShieldGuard version is available."""
    if not repo or "YOUR_GITHUB_USERNAME" in repo:
        return {
            "ok": False,
            "configured": False,
            "error": "GitHub repository is not configured yet (set __github_repo__ in shieldguard/__init__.py).",
        }

    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        resp = requests.get(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "ShieldGuard-Updater/1.0"},
            timeout=timeout,
        )
        if resp.status_code == 404:
            return {"ok": False, "configured": True, "error": "No GitHub Release published yet."}
        if resp.status_code != 200:
            return {"ok": False, "configured": True, "error": f"GitHub API HTTP {resp.status_code}"}

        data = resp.json()
        latest_tag = str(data.get("tag_name") or "").lstrip("vV").strip()
        html_url = str(data.get("html_url") or f"https://github.com/{repo}/releases")
        notes = str(data.get("body") or "").strip()

        download_url = html_url
        for asset in data.get("assets") or []:
            name = str(asset.get("name") or "").lower()
            if name.endswith(".exe"):
                download_url = str(asset.get("browser_download_url") or html_url)
                break

        has_update = is_newer_version(latest_tag, __version__)
        return {
            "ok": True,
            "configured": True,
            "current_version": __version__,
            "latest_version": latest_tag or __version__,
            "has_update": has_update,
            "release_url": html_url,
            "download_url": download_url,
            "notes": notes[:600],
        }
    except requests.ConnectionError:
        return {"ok": False, "configured": True, "offline": True, "error": "No Internet connection."}
    except Exception as exc:
        return {"ok": False, "configured": True, "error": str(exc)}


def trigger_winget_upgrade(package_id: str = __winget_id__) -> Tuple[bool, str]:
    """Launch winget upgrade in a visible PowerShell window so the user can watch progress."""
    if not package_id or "YOUR_GITHUB_USERNAME" in package_id:
        return False, "WinGet Package ID is not configured yet."
    try:
        subprocess.Popen(
            ["powershell.exe", "-NoExit", "-Command", f"winget upgrade --id {package_id} --exact"],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        return True, f"Started: winget upgrade --id {package_id}"
    except Exception as exc:
        return False, str(exc)
