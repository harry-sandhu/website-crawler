from audit.models import Issue


def run_sticky_audit(result):
    issues = []

    sticky = []

    for element in result.elements:

        if element.fixed or element.sticky:
            sticky.append(element)

    if not sticky:
        return issues

    evidence = []

    for element in sticky[:10]:

        evidence.append(
            f"{element.tag} ({element.position})"
        )

    issues.append(
        Issue(
            category="Responsive",
            severity="Low",
            title=f"Sticky Elements ({result.device})",
            description=f"{len(sticky)} fixed/sticky elements detected.",
            recommendation="Ensure sticky elements do not cover important content.",
            screenshot=f"{result.device}.png",
            evidence="\n".join(evidence),
        )
    )

    return issues