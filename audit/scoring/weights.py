# ==========================================
# Starting Score
# ==========================================

MAX_SCORE = 100


# ==========================================
# Severity Deductions
# ==========================================

SEVERITY_WEIGHTS = {

    "Critical": 15,

    "High": 8,

    "Medium": 4,

    "Low": 1,

    "Info": 0,

}


# ==========================================
# Category Multipliers
# ==========================================

CATEGORY_MULTIPLIERS = {

    "SEO": 1.00,

    "Performance": 1.20,

    "Security": 1.20,

    "Accessibility": 1.10,

    "Responsive": 1.00,

    "Network": 0.80,

    "Console": 0.50,

    "Lighthouse": 0.75,

    "HTML Best Practices": 0.70,

    "HTML/UX": 0.30,

    "Networking": 0.80,

    "Authentication": 1.10,

    "Business Logic": 1.10,

    "Detected Technologies": 0.10,

    "Usability": 0.80,

    "Visual Design": 1.00,

    "Links": 0.90,

    "Forms": 0.70,

    "Trust & Compliance": 0.80,

}


# ==========================================
# Minimum Score
# ==========================================

MIN_SCORE = 0


# ==========================================
# Categories that are always audited
# (they start at 100 even with zero issues,
# so a clean category lifts the overall score)
# ==========================================

AUDITED_CATEGORIES = [

    "SEO",

    "Performance",

    "Security",

    "Accessibility",

    "Responsive",

    "Visual Design",

    "Links",

    "Network",

    "Console",

    "Trust & Compliance",

]
