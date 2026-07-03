from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.enums import TA_CENTER

# ----------------------------------
# Base Styles
# ----------------------------------

_styles = getSampleStyleSheet()

TITLE = _styles["Heading1"]
TITLE.alignment = TA_CENTER
TITLE.spaceAfter = 20

HEADING = _styles["Heading2"]
HEADING.spaceBefore = 18
HEADING.spaceAfter = 10

SUBHEADING = _styles["Heading3"]

BODY = _styles["BodyText"]

SMALL = _styles["BodyText"]
SMALL.fontSize = 9
SMALL.leading = 12

# ----------------------------------
# Severity Colors
# ----------------------------------

CRITICAL = colors.HexColor("#dc2626")
HIGH = colors.HexColor("#ea580c")
MEDIUM = colors.HexColor("#d97706")
LOW = colors.HexColor("#16a34a")

PRIMARY = colors.HexColor("#2563eb")
BORDER = colors.HexColor("#d1d5db")
BACKGROUND = colors.HexColor("#f8fafc")
TEXT = colors.HexColor("#1f2937")