from audit.models import Issue


def run_seo_audit(page_data):
    issues = []

    # ==========================================================
    # Title
    # ==========================================================

    title = page_data["title"]

    if not title:
        issues.append(
            Issue(
                category="SEO",
                severity="Critical",
                title="Missing Page Title",
                description="The page does not have a title.",
                recommendation="Add a descriptive <title> tag."
            )
        )

    elif len(title) < 20:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Title Too Short",
                description=f"Title length is {len(title)} characters.",
                recommendation="Aim for 50–60 characters."
            )
        )

    elif len(title) > 60:
        issues.append(
            Issue(
                category="SEO",
                severity="Low",
                title="Title Too Long",
                description=f"Title length is {len(title)} characters.",
                recommendation="Keep the title below about 60 characters."
            )
        )

    # ==========================================================
    # Meta Description
    # ==========================================================

    meta_description = page_data["meta"].get("description")

    if not meta_description:
        issues.append(
            Issue(
                category="SEO",
                severity="High",
                title="Missing Meta Description",
                description="No meta description was found.",
                recommendation="Add a compelling 150–160 character meta description."
            )
        )

    elif len(meta_description) < 120:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Meta Description Too Short",
                description=f"Meta description is only {len(meta_description)} characters.",
                recommendation="Aim for 150–160 characters."
            )
        )

    # ==========================================================
    # H1
    # ==========================================================

    h1_count = len(page_data["headings"]["h1"])

    if h1_count == 0:
        issues.append(
            Issue(
                category="SEO",
                severity="Critical",
                title="Missing H1 Heading",
                description="No H1 heading was found.",
                recommendation="Add one descriptive H1 heading."
            )
        )

    elif h1_count > 1:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Multiple H1 Headings",
                description=f"{h1_count} H1 headings were found.",
                recommendation="Use only one H1 heading per page."
            )
        )

    # ==========================================================
    # Canonical
    # ==========================================================

    if not page_data["canonical"]:
        issues.append(
            Issue(
                category="SEO",
                severity="High",
                title="Missing Canonical Tag",
                description="No canonical URL was found.",
                recommendation="Add a canonical link element."
            )
        )

    # ==========================================================
    # Viewport
    # ==========================================================

    if not page_data["viewport"]:
        issues.append(
            Issue(
                category="SEO",
                severity="High",
                title="Missing Viewport Meta Tag",
                description="Responsive viewport tag is missing.",
                recommendation="Add a viewport meta tag."
            )
        )

    # ==========================================================
    # HTML Language
    # ==========================================================

    if not page_data["lang"]:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Missing HTML Language",
                description="The HTML document has no lang attribute.",
                recommendation="Specify the page language."
            )
        )

    # ==========================================================
    # Favicon
    # ==========================================================

    if not page_data["favicon"]:
        issues.append(
            Issue(
                category="SEO",
                severity="Low",
                title="Missing Favicon",
                description="No favicon was detected.",
                recommendation="Provide a favicon."
            )
        )

    # ==========================================================
    # Structured Data
    # ==========================================================

    if len(page_data["schema"]) == 0:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Missing Structured Data",
                description="No JSON-LD structured data was found.",
                recommendation="Add structured data where appropriate."
            )
        )

    # ==========================================================
    # Open Graph
    # ==========================================================

    og_tags = [
        "og:title",
        "og:description",
        "og:image",
    ]

    for tag in og_tags:
        if tag not in page_data["meta"]:
            issues.append(
                Issue(
                    category="SEO",
                    severity="Medium",
                    title=f"Missing {tag}",
                    description=f"{tag} metadata is missing.",
                    recommendation="Add the required Open Graph tag."
                )
            )

    # ==========================================================
    # Twitter Cards
    # ==========================================================

    twitter_tags = [
        "twitter:card",
        "twitter:title",
        "twitter:description",
    ]

    for tag in twitter_tags:
        if tag not in page_data["meta"]:
            issues.append(
                Issue(
                    category="SEO",
                    severity="Low",
                    title=f"Missing {tag}",
                    description=f"{tag} metadata is missing.",
                    recommendation="Add Twitter Card metadata."
                )
            )

    # ==========================================================
    # Images
    # ==========================================================

    missing_alt = []

    for img in page_data["images"]:
        src = img.get("src") or ""

        # Ignore placeholder SVGs
        if src.startswith("data:image"):
            continue

        alt = img.get("alt")

        if alt is None or alt.strip() == "":
            missing_alt.append(src)

    if missing_alt:
        issues.append(
            Issue(
                category="SEO",
                severity="Medium",
                title="Images Missing Alt Text",
                description=f"{len(missing_alt)} images are missing alt text.",
                recommendation="Add descriptive alt text to all meaningful images.",
                evidence="\n".join(missing_alt[:10])
            )
        )

    # ==========================================================
    # Lazy Loading
    # ==========================================================

    total_images = len(page_data["images"])

    if total_images > 0:
        lazy_images = sum(
            1
            for img in page_data["images"]
            if img.get("loading") == "lazy"
        )

        if lazy_images < total_images / 2:
            issues.append(
                Issue(
                    category="SEO",
                    severity="Low",
                    title="Images Not Using Lazy Loading",
                    description=f"Only {lazy_images} of {total_images} images use lazy loading.",
                    recommendation="Use loading='lazy' for below-the-fold images."
                )
            )

    return issues