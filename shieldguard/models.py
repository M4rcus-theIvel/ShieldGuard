from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def label_vi(self) -> str:
        from .i18n import t

        return t(f"sev_{self.value}")

    @property
    def color(self) -> str:
        return {
            Severity.CRITICAL: "#ef4444",
            Severity.HIGH: "#f97316",
            Severity.MEDIUM: "#eab308",
            Severity.LOW: "#3b82f6",
            Severity.INFO: "#6b7280",
        }[self]

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class ThreatCategory(str, Enum):
    PROCESS = "PROCESS"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    REGISTRY = "REGISTRY"
    STARTUP_FILE = "STARTUP_FILE"
    SERVICE = "SERVICE"
    WMI = "WMI"
    DEFENDER_EXCLUSION = "DEFENDER_EXCLUSION"
    FILE = "FILE"

    @property
    def label_vi(self) -> str:
        from .i18n import t

        return t(f"cat_{self.value}")


@dataclass
class ThreatFinding:
    title: str
    category: ThreatCategory
    severity: Severity
    target: str
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    detected_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    remediated: bool = False
    title_key: str = ""
    title_args: Dict[str, Any] = field(default_factory=dict)
    reason_key: str = ""
    reason_args: Dict[str, Any] = field(default_factory=dict)
    reason_keys: list[tuple[str, Dict[str, Any]]] = field(default_factory=list)

    @property
    def display_title(self) -> str:
        if self.title_key:
            from .i18n import t

            return t(self.title_key, **self.title_args)
        return self.title

    @property
    def display_reason(self) -> str:
        from .i18n import t

        if self.reason_keys:
            return "; ".join(t(k, **kw) for k, kw in self.reason_keys)
        if self.reason_key:
            return t(self.reason_key, **self.reason_args)
        return self.reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.display_title,
            "category": self.category.value,
            "severity": self.severity.value,
            "target": self.target,
            "reason": self.display_reason,
            "details": self.details,
            "detected_at": self.detected_at,
            "remediated": self.remediated,
        }


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    quarantine_path: str
    threat_title: str
    sha256: str
    quarantined_at: str
    size_bytes: int
    restored: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "original_path": self.original_path,
            "quarantine_path": self.quarantine_path,
            "threat_title": self.threat_title,
            "sha256": self.sha256,
            "quarantined_at": self.quarantined_at,
            "size_bytes": self.size_bytes,
            "restored": self.restored,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QuarantineItem":
        return cls(
            id=data["id"],
            original_path=data["original_path"],
            quarantine_path=data["quarantine_path"],
            threat_title=data.get("threat_title", "Unknown"),
            sha256=data.get("sha256", ""),
            quarantined_at=data.get("quarantined_at", ""),
            size_bytes=int(data.get("size_bytes", 0)),
            restored=bool(data.get("restored", False)),
        )
