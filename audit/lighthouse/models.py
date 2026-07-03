from dataclasses import dataclass, field


@dataclass
class LighthouseCategory:
    id: str
    title: str
    score: float


@dataclass
class LighthouseMetric:
    name: str
    value: float | str
    unit: str = ""


@dataclass
class LighthouseAudit:
    categories: list[LighthouseCategory] = field(default_factory=list)
    metrics: list[LighthouseMetric] = field(default_factory=list)
    opportunities: list = field(default_factory=list)
    diagnostics: list = field(default_factory=list)
    issues: list = field(default_factory=list)