from dataclasses import dataclass, asdict


@dataclass
class Issue:
    category: str
    severity: str

    title: str
    description: str
    recommendation: str

    evidence: str = ""

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
