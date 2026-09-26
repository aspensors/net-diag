"""Immutable-ish data transfer objects used by the diagnostic engine."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Outcome(str, Enum):
    OK = "ok"
    WARNING = "warning"
    FAILED = "failed"
    SKIPPED = "skipped"


class VerdictKind(str, Enum):
    CLEAN = "OK: Clean"
    DNS_POISONING = "DNS Poisoning Detected"
    TCP_DROP = "IP Blacklist / TCP Drop"
    DPI_SNI = "DPI SNI Block"
    HTTP_HIJACK = "HTTP Hijack / Redirect Block"
    INCONCLUSIVE = "Inconclusive"


@dataclass(slots=True)
class ProbeOptions:
    timeout_seconds: float = 7.0
    test_port_80: bool = False
    max_ips: int = 4
    user_agent: str = "net-diag/1.0 (+diagnostic)"


@dataclass(slots=True)
class StageResult:
    stage: str
    outcome: Outcome
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float | None = None


@dataclass(slots=True)
class TcpAttempt:
    address: str
    port: int
    outcome: Outcome
    elapsed_ms: float | None
    error_kind: str | None = None
    message: str | None = None


@dataclass(slots=True)
class TlsAttempt:
    address: str
    sni: str | None
    outcome: Outcome
    elapsed_ms: float | None
    error_kind: str | None = None
    message: str | None = None
    tls_version: str | None = None
    cipher: str | None = None


@dataclass(slots=True)
class Verdict:
    kind: VerdictKind
    confidence: str
    summary: str
    recommendations: list[str]


@dataclass(slots=True)
class CheckReport:
    domain: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    stages: list[StageResult] = field(default_factory=list)
    system_ips: list[str] = field(default_factory=list)
    doh_ips: dict[str, list[str]] = field(default_factory=dict)
    tcp: list[TcpAttempt] = field(default_factory=list)
    tls_with_sni: list[TlsAttempt] = field(default_factory=list)
    tls_without_sni: list[TlsAttempt] = field(default_factory=list)
    http_status: int | None = None
    http_url: str | None = None
    http_headers: dict[str, str] = field(default_factory=dict)
    http_suspected_hijack: bool = False
    http_error: str | None = None
    verdict: Verdict | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation suitable for an audit report."""
        return asdict(self)
