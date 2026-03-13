from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    check: str
    result: str  # "VULNERABLE" | "MISCONFIGURED" | "INFO" | "SECURE"
    severity: str  # "Critical" | "High" | "Medium" | "Low" | "Info"
    evidence: str
    detail: str = ""
    raw_request: str = ""
    raw_response: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "result": self.result,
            "severity": self.severity,
            "evidence": self.evidence,
            "detail": self.detail,
            "raw_request": self.raw_request,
            "raw_response": self.raw_response[:500] if self.raw_response else "",
            "extra": self.extra,
        }


class BaseScanModule(ABC):
    name: str = "base"
    description: str = ""

    def __init__(self, timeout: int = 10, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose

    @abstractmethod
    def run(self, url: str) -> list[Finding]:
        """Execute the scan module against the target URL."""

    @staticmethod
    def _elapsed(start: float) -> str:
        return f"{time.time() - start:.2f}s"
