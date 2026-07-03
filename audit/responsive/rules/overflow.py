from audit.models import Issue

from audit.filters import visible_elements


def run_overflow_audit(result):
    issues = []

    # =====================================================
    # Horizontal Page Scrolling
    # =====================================================

    if result.scroll_width > result.client_width:

        issues.append(
            Issue(
                category="Responsive",
                severity="High",
                title=f"Horizontal Scrolling ({result.device})",
                description="The page is wider than the viewport.",
                recommendation="Ensure all page content fits within the viewport.",
                screenshot=f"{result.device}.png",
                evidence=(
                    f"Viewport Width : {result.client_width}px\n"
                    f"Page Width     : {result.scroll_width}px"
                ),
            )
        )

    # =====================================================
    # Oversized Elements
    # =====================================================

    oversized = []

    for element in visible_elements(result.elements):

        if element.width > result.width + 5:
            oversized.append(element)

    if oversized:

        evidence = []

        for element in oversized[:10]:

            selector = element.selector

            if not selector:
                selector = element.tag.lower()

            evidence.append(
                f"{selector} ({element.width:.0f}px)"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="Medium",
                title=f"Oversized Elements ({result.device})",
                description=f"{len(oversized)} elements exceed the viewport width.",
                recommendation="Resize or constrain overflowing elements.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    # =====================================================
    # Off-screen Elements
    # =====================================================

    offscreen = []

    for element in visible_elements(result.elements):

        if element.overflow_x:
            offscreen.append(element)

    if offscreen:

        evidence = []

        for element in offscreen[:10]:

            selector = element.selector

            if not selector:
                selector = element.tag.lower()

            evidence.append(
                f"{selector} → right={element.right:.0f}px"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="Medium",
                title=f"Off-screen Elements ({result.device})",
                description=f"{len(offscreen)} elements extend beyond the viewport.",
                recommendation="Ensure elements remain fully visible on all screen sizes.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    return issues