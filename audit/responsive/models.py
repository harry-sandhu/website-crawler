from dataclasses import dataclass, field


# =====================================================
# Individual DOM Element
# =====================================================

@dataclass
class ResponsiveElement:

    # ---------------- Basic ---------------- #

    tag: str

    id: str
    classes: str

    selector: str
    parent: str

    text: str

    # ---------------- Position ---------------- #

    x: float
    y: float

    width: float
    height: float

    top: float
    left: float
    right: float
    bottom: float

    # ---------------- Visibility ---------------- #

    visible: bool

    display: str
    visibility: str
    opacity: str

    # ---------------- Positioning ---------------- #

    position: str

    fixed: bool
    sticky: bool

    z_index: str

    # ---------------- Overflow ---------------- #

    overflow_x: bool
    overflow_y: bool

    scroll_width: float
    scroll_height: float

    client_width: float
    client_height: float

    # ---------------- Accessibility ---------------- #

    role: str
    aria_label: str

    # ---------------- Images ---------------- #

    src: str
    srcset: str
    sizes: str
    loading: str

    natural_width: int
    natural_height: int

    # ---------------- Links ---------------- #

    href: str


# =====================================================
# Entire Responsive Scan
# =====================================================

@dataclass
class ResponsiveResult:

    device: str

    width: int
    height: int

    scroll_width: int
    client_width: int

    oversized: list = field(default_factory=list)

    fixed_elements: list = field(default_factory=list)

    elements: list[ResponsiveElement] = field(default_factory=list)