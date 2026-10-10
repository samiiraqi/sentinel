"""Shared data models used by all Sentinel agents."""

from dataclasses import asdict, dataclass

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Finding:
    """One issue found by an agent. Never holds a full secret."""

    agent: str
    rule_id: str
    severity: str  # one of SEVERITIES
    file: str
    line: int
    message: str
    redacted_match: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")

    def to_dict(self) -> dict:
        return asdict(self)
