from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import platform
from typing import Any, Dict, List, Optional

from . import __app_name__, __version__
from .models import Severity, ThreatFinding
from .utils import is_admin


def default_log_filename(ext: str = ".txt") -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"ShieldGuard_Report_{stamp}{ext}"


def format_text_report(
    findings: List[ThreatFinding],
    scan_scope: str = "Full System Scan",
    gpu_info: Optional[Dict[str, Any]] = None,
) -> str:
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {sev: 0 for sev in Severity}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines: List[str] = [
        "=" * 72,
        f"  {__app_name__} v{__version__} — MALWARE SCAN REPORT",
        "=" * 72,
        f"Generated At : {now_str}",
        f"Scan Scope   : {scan_scope}",
        f"System OS    : {platform.system()} {platform.release()} ({platform.version()})",
        f"Admin Mode   : {'Yes' if is_admin() else 'No'}",
    ]

    if gpu_info and gpu_info.get("available"):
        lines.append(
            f"NVIDIA GPU   : {gpu_info.get('gpu_name', '')} | "
            f"Util {gpu_info.get('util_pct', 0)}% | "
            f"VRAM {gpu_info.get('mem_used_mb', 0)}/{gpu_info.get('mem_total_mb', 0)} MB | "
            f"Temp {gpu_info.get('temp_c', 0)}C"
        )

    lines.extend(
        [
            "-" * 72,
            f"SUMMARY: Total Findings = {len(findings)}",
            f"  CRITICAL: {counts[Severity.CRITICAL]} | "
            f"HIGH: {counts[Severity.HIGH]} | "
            f"MEDIUM: {counts[Severity.MEDIUM]} | "
            f"LOW: {counts[Severity.LOW]} | "
            f"INFO: {counts[Severity.INFO]}",
            "=" * 72,
            "",
        ]
    )

    if not findings:
        lines.append("No threats or suspicious items detected.")
        return "\n".join(lines)

    for idx, f in enumerate(findings, start=1):
        status = "REMEDIATED" if f.remediated else "ACTIVE"
        lines.extend(
            [
                f"[{idx}] [{f.severity.value}] [{f.category.value}] ({status})",
                f"  Title   : {f.display_title}",
                f"  Target  : {f.target}",
                f"  Reason  : {f.display_reason}",
                f"  Time    : {f.detected_at}",
            ]
        )
        if f.details:
            for k, v in f.details.items():
                if v not in (None, "", []):
                    lines.append(f"  {k:<8}: {v}")
        lines.append("-" * 72)

    return "\n".join(lines)


def export_findings_log(
    findings: List[ThreatFinding],
    output_path: str | Path,
    scan_scope: str = "Full System Scan",
    gpu_info: Optional[Dict[str, Any]] = None,
) -> Path:
    """Export findings to a shareable .txt or .json log file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.suffix.lower() == ".json":
        payload = {
            "app": __app_name__,
            "version": __version__,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_scope": scan_scope,
            "os": f"{platform.system()} {platform.release()}",
            "admin_mode": is_admin(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        content = format_text_report(findings, scan_scope=scan_scope, gpu_info=gpu_info)
        path.write_text(content, encoding="utf-8")

    return path
