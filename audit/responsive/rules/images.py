from audit.models import Issue

from audit.filters import image_elements


def run_image_audit(result):
    issues = []

    images = image_elements(result.elements)

    if not images:
        return issues

    # =====================================================
    # Oversized Images
    # =====================================================

    oversized = []

    for image in images:

        if (
            image.natural_width > 0
            and image.width > 0
            and image.natural_width > image.width * 2
        ):
            oversized.append(image)

    if oversized:

        evidence = []

        for image in oversized[:10]:

            selector = image.selector or "img"

            evidence.append(
                f"{selector} ({image.natural_width}px → {image.width:.0f}px)"
            )

        issues.append(
            Issue(
                category="Responsive",
                severity="Low",
                title=f"Oversized Images ({result.device})",
                description=f"{len(oversized)} images are significantly larger than their rendered size.",
                recommendation="Serve appropriately sized images or use responsive image techniques.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    # =====================================================
    # Missing Lazy Loading
    # =====================================================

    missing_lazy = []

    for image in images:

        if image.loading.lower() != "lazy":
            missing_lazy.append(image)

    if missing_lazy:

        evidence = []

        for image in missing_lazy[:10]:

            selector = image.selector or "img"

            evidence.append(selector)

        issues.append(
            Issue(
                category="Responsive",
                severity="Low",
                title=f"Images Without Lazy Loading ({result.device})",
                description=f"{len(missing_lazy)} images are not using loading='lazy'.",
                recommendation="Use lazy loading for below-the-fold images.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    # =====================================================
    # Missing Responsive Images
    # =====================================================

    responsive_missing = []

    for image in images:

        if not image.srcset:
            responsive_missing.append(image)

    if responsive_missing:

        evidence = []

        for image in responsive_missing[:10]:

            selector = image.selector or "img"

            evidence.append(selector)

        issues.append(
            Issue(
                category="Responsive",
                severity="Low",
                title=f"Missing Responsive Images ({result.device})",
                description=f"{len(responsive_missing)} images do not provide a srcset attribute.",
                recommendation="Use srcset and sizes so browsers can download appropriately sized images.",
                screenshot=f"{result.device}.png",
                evidence="\n".join(evidence),
            )
        )

    return issues