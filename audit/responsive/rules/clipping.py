from audit.models import Issue

from audit.filters import visible_elements


def run_clipping_audit(result):
    issues = []

    clipped = []

    for element in visible_elements(result.elements):

        # Ignore tiny elements
        if element.width < 10 or element.height < 10:
            continue

        # Ignore large containers
        if element.tag in (
            "HTML",
            "BODY",
            "MAIN",
        ):
            continue

        # Horizontal clipping
        horizontal = (
            element.scroll_width > element.client_width + 5
        )

        # Vertical clipping
        vertical = (
            element.scroll_height > element.client_height + 5
        )

        if horizontal or vertical:
            clipped.append(element)

    if not clipped:
        return issues

    evidence = []

    for element in clipped[:10]:

        selector = element.selector or element.tag.lower()

        reason = []

        if element.scroll_width > element.client_width + 5:
            reason.append(
                f"W {element.client_width:.0f}->{element.scroll_width:.0f}"
            )

        if element.scroll_height > element.client_height + 5:
            reason.append(
                f"H {element.client_height:.0f}->{element.scroll_height:.0f}"
            )

        evidence.append(
            f"{selector} ({', '.join(reason)})"
        )

    issues.append(
        Issue(
            category="Responsive",
            severity="Medium",
            title=f"Content Clipping ({result.device})",
            description=f"{len(clipped)} elements appear to clip their content.",
            recommendation="Increase available space or remove restrictive overflow settings.",
            screenshot=f"{result.device}.png",
            evidence="\n".join(evidence),
        )
    )

    return issues