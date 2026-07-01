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
    page: str = ""
    selector: str = ""
    screenshot: str = ""
    fix_time: str = ""

    def to_dict(self):
        return asdict(self)