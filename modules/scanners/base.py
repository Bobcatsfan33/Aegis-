"""
Abstract base classes shared by all scanner implementations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


@dataclass
class Finding:
    """A single security issue detected during a scan."""

    resource: str           # Identifier of the affected resource (bucket name, SG id, IP:port, etc.)
    issue: str              # Short description of the problem
    severity: str           # "critical" | "high" | "medium" | "low" | "info"
    provider: str           # "aws" | "azure" | "gcp" | "network"
    region: Optional[str] = None
    resource_type: Optional[str] = None   # e.g. "s3_bucket", "security_group", "open_port"
    details: dict = field(default_factory=dict)
    remediation_hint: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "issue": self.issue,
            "severity": self.severity,
            "provider": self.provider,
            "region": self.region,
            "resource_type": self.resource_type,
            "details": self.details,
            "remediation_hint": self.remediation_hint,
            "timestamp": self.timestamp,
        }


class BaseScanner(ABC):
    """Abstract base class that all cloud/network scanners must implement."""

    provider: str = "unknown"

    @abstractmethod
    def scan(self) -> List[Finding]:
        """Run all checks and return a list of Findings."""
        ...

    def is_available(self) -> bool:
        """
        Return True if this scanner's dependencies and credentials are present.
        Called before scan() to decide whether to include this scanner in a run.
        """
        return True
