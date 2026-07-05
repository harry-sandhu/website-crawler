from dataclasses import dataclass, field


@dataclass
class ReportSection:

    title: str

    issues: list = field(default_factory=list)


@dataclass
class ReportModel:

    # ----------------------------------
    # Website
    # ----------------------------------

    url: str

    title: str

    generated_at: str

    # ----------------------------------
    # Scores
    # ----------------------------------

    overall_score: float

    category_scores: list = field(default_factory=list)

    # ----------------------------------
    # Issue Counts
    # ----------------------------------

    critical: int = 0

    high: int = 0

    medium: int = 0

    low: int = 0

    info: int = 0

    total_issues: int = 0

    raw_issues: int = 0

    # ----------------------------------
    # Website Information
    # ----------------------------------

    browser: dict = field(default_factory=dict)

    page: dict = field(default_factory=dict)

    # ----------------------------------
    # Screenshots
    # ----------------------------------

    screenshots: dict = field(default_factory=dict)

    # ----------------------------------
    # Sections
    # ----------------------------------

    sections: list[ReportSection] = field(default_factory=list)
