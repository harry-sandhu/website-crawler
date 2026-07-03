from audit.models import Issue

MIN_SIZE = 48


def run_touch_target_audit(result):
    issues = []

    bad = []

    for element in result.elements:

        if not element.visible:
            continue

        if element.tag not in (
            "BUTTON",
            "A",
            "INPUT",
            "TEXTAREA",
            "SELECT",
        ):
            continue

        if element.width < MIN_SIZE or element.height < MIN_SIZE:
            bad.append(element)

    if bad:

        evidence = []

        for element in bad[:10]:
            evidence.append(
                f"{element.tag} ({element.width:.0f}x{element.height:.0f}px)"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="Medium",
                title=f"Small Touch Targets ({result.device})",
                description=f"{len(bad)} touch targets are smaller than 48×48px.",
                recommendation="Increase button/link padding for mobile users.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    return issues