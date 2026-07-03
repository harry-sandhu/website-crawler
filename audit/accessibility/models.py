from dataclasses import dataclass, field


@dataclass
class AccessibilityViolation:

    id: str

    impact: str

    description: str

    help: str

    help_url: str

    nodes: list = field(default_factory=list)


@dataclass
class AccessibilitySummary:

    violations: list[AccessibilityViolation] = field(default_factory=list)

    passes: int = 0

    incomplete: int = 0

    inapplicable: int = 0