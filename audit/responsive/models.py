from dataclasses import dataclass, field


@dataclass
class ResponsiveResult:
    device: str

    width: int
    height: int

    scroll_width: int
    client_width: int

    oversized: list = field(default_factory=list)
    fixed_elements: list = field(default_factory=list)