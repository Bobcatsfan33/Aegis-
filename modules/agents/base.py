"""
Abstract base class for all remediation agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

from modules.scanners.base import Finding


@dataclass
class RemediationResult:
    """The outcome of a single remediation action."""

    success: bool
    action_taken: str
    details: str
    dry_run: bool = False
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "action_taken": self.action_taken,
            "details": self.details,
            "dry_run": self.dry_run,
            "error": self.error,
        }


class BaseAgent(ABC):
    """All remediation agents extend this class."""

    def __init__(self, dry_run: bool = True):
        # dry_run=True  → log what would happen, make no changes
        # dry_run=False → execute the remediation for real
        self.dry_run = dry_run

    @abstractmethod
    def can_handle(self, finding: Finding) -> bool:
        """Return True if this agent knows how to remediate the given Finding."""
        ...

    @abstractmethod
    def remediate(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        """Execute (or simulate) the remediation and return the result."""
        ...
