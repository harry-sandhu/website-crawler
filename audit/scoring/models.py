from dataclasses import dataclass, field


@dataclass
class CategoryScore:

    name: str

    score: float

    deductions: float = 0


@dataclass
class AuditScore:

    overall: float = 100

    categories: list[CategoryScore] = field(default_factory=list)

    critical: int = 0

    high: int = 0

    medium: int = 0

    low: int = 0

    info: int = 0

    total_issues: int = 0

    raw_issues: int = 0
