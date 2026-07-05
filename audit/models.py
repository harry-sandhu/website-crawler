from dataclasses import dataclass, asdict, field


@dataclass
class Issue:
    category: str
    severity: str

    title: str
    description: str
    recommendation: str

    evidence: str = ""
    finding_key: str = ""
    affected_item: str = ""
    affected_items: list[str] = field(default_factory=list)
    occurrences: int = 1
    verification: str = "Potential"

    # Optional
    endpoint: str = ""
    page: str = ""
    selector: str = ""
    parameter: str = ""
    payload: str = ""
    original_value: str = ""
    modified_value: str = ""
    response_code: int | None = None
    response_time: float | None = None
    impact: str = ""
    confidence: str = ""
    cwe: str = ""
    owasp: str = ""
    screenshot: str = ""
    fix_time: str = ""
    notes: str = ""

    def to_dict(self):
        return asdict(self)
