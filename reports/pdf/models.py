from dataclasses import dataclass, field


@dataclass
class PDFSection:

    title: str

    issues: list = field(
        default_factory=list
    )


@dataclass
class PDFReportModel:

    url: str

    title: str

    generated_at: str

    overall_score: float

    category_scores: list

    critical: int

    high: int

    medium: int

    low: int

    total_issues: int

    browser: dict

    page: dict

    screenshots: dict

    sections: list