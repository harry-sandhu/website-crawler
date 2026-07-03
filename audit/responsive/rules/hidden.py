from audit.models import Issue

from audit.filters import all_elements


def run_hidden_audit(result):
    issues = []

    hidden = []

    for element in all_elements(result.elements):

        

        # We only care about elements that are intentionally
        # hidden after filtering.
        if element.visible:
            continue

        hidden.append(element)

    if not hidden:
        return issues

    evidence = []

    for element in hidden[:10]:

        selector = element.selector or element.tag.lower()

        reason = []

        if element.display == "none":
            reason.append("display:none")

        if element.visibility == "hidden":
            reason.append("visibility:hidden")

        if element.opacity == "0":
            reason.append("opacity:0")

        if not reason:
            reason.append("hidden")

        evidence.append(
            f"{selector} ({', '.join(reason)})"
        )

    issues.append(
        Issue(
            category="Responsive",
            severity="Low",
            title=f"Hidden Elements ({result.device})",
            description=f"{len(hidden)} visible-page elements are hidden.",
            recommendation="Verify these elements are intentionally hidden for this viewport.",
            screenshot=f"{result.device}.png",
            evidence="\n".join(evidence),
        )
    )

    return issues