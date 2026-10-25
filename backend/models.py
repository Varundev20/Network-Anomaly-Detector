"""Plain data objects shared by the detector, storage and investigator."""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Alert:
    rule_name: str
    severity_label: str
    source: str
    measured_value: int        # peak value across the merged windows
    threshold: int
    window_start: str          # ISO time of the first window
    window_end: str            # ISO time the last window ends
    window_count: int
    evidence: dict[str, Any] = field(default_factory=dict)
    alert_id: int | None = None
    dataset: str = ""
    status: str = "new"
    created_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    requested_by: str          # "model" or "app" (app = model skipped it)


@dataclass
class Investigation:
    alert_id: int
    model: str
    status: str                # "ok" or "fallback"
    report: dict[str, Any]
    tool_calls: list[ToolCall] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    tokens_generated: int = 0
    tokens_per_second: float | None = None
    error: str | None = None
    started_at: str = ""
    investigation_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
