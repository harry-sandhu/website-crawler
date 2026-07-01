from dataclasses import dataclass, field

from audit.models import Issue


@dataclass
class AuditReport:
    issues: list[Issue] = field(default_factory=list)

    seo_score: int | None = None
    performance_score: int | None = None
    accessibility_score: int | None = None
    security_score: int | None = None
    network_score: int | None = None
    console_score: int | None = None

    summary: dict = field(default_factory=dict)