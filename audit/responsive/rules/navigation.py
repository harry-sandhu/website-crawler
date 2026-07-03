from audit.models import Issue

from audit.filters import navigation_elements


def run_navigation_audit(result):
    issues = []

    navs = navigation_elements(result.elements)

    # =====================================================
    # Missing Navigation
    # =====================================================

    if not navs:

        issues.append(
            Issue(
                category="Responsive",
                severity="Medium",
                title=f"Navigation Not Detected ({result.device})",
                description="No semantic navigation element was detected.",
                recommendation="Use <nav> or role='navigation' for better accessibility and SEO.",
                screenshot=f"{result.device}.png",
            )
        )

        return issues

    # =====================================================
    # Overflowing Navigation
    # =====================================================

    overflowing = []

    for nav in navs:

        if nav.width > result.width + 5:
            overflowing.append(nav)
            continue

        if nav.overflow_x:
            overflowing.append(nav)

    if overflowing:

        evidence = []

        for nav in overflowing[:10]:

            selector = nav.selector or nav.tag.lower()

            evidence.append(
                f"{selector} ({nav.width:.0f}px)"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="High",
                title=f"Navigation Overflow ({result.device})",
                description=f"{len(overflowing)} navigation element(s) exceed the viewport width.",
                recommendation="Collapse the navigation into a mobile menu or allow wrapping.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    # =====================================================
    # Very Small Navigation
    # =====================================================

    tiny = []

    for nav in navs:

        if nav.height < 40:
            tiny.append(nav)

    if tiny:

        evidence = []

        for nav in tiny[:10]:

            selector = nav.selector or nav.tag.lower()

            evidence.append(
                f"{selector} ({nav.height:.0f}px high)"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="Low",
                title=f"Small Navigation ({result.device})",
                description=f"{len(tiny)} navigation element(s) may be difficult to use on touch devices.",
                recommendation="Increase navigation height and spacing for mobile usability.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    return issues