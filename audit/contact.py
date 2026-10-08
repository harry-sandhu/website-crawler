from audit.models import Issue

CATEGORY = "Trust & Compliance"


def _issue(severity, title, description, recommendation, evidence=""):

    return Issue(
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        confidence="High",
        verification_method="Content inspection",
    )


def run_contact_audit(website):

    issues = []

    page = website.page
    soup = page["soup"]

    links = [
        ((l.get("href") or "").lower(), (l.get("text") or "").lower())
        for l in page["links"]
    ]

    def has_link(*keywords):

        return any(
            any(k in href or k in text for k in keywords)
            for href, text in links
        )

    # ---------- contact ----------

    if not page["phones"] and not page["emails"] and not soup.find("form"):

        issues.append(_issue(
            "High", "No Way to Contact the Business",
            "No phone number, email address or contact form was found.",
            "Show contact details prominently in the header or footer.",
        ))

    elif not page["phones"]:

        issues.append(_issue(
            "Low", "No Click-to-Call Link",
            "No tel: link exists, so mobile users cannot tap to call.",
            "Wrap phone numbers in <a href='tel:...'>.",
        ))

    if not has_link("contact", "contatt", "kontakt", "contacto"):

        issues.append(_issue(
            "Low", "No Contact Page Link",
            "Navigation has no link to a contact page.",
            "Add a Contact link to the main menu or footer.",
        ))

    # ---------- legal ----------

    if not has_link("privacy", "datenschutz", "confidentialit"):

        issues.append(_issue(
            "Medium", "No Privacy Policy Link",
            "No privacy policy link was found (legally required where "
            "personal data or cookies are used).",
            "Link a privacy policy from the footer on every page.",
        ))

    if not has_link("terms", "condizioni", "termini", "imprint", "impressum", "legal"):

        issues.append(_issue(
            "Low", "No Terms or Legal Notice Link",
            "No terms of use, imprint or legal notice link was found.",
            "Add legal pages to the footer.",
        ))

    # ---------- cookie consent ----------

    html = page["html"].lower()

    consent_tools = (
        "cookiebot", "iubenda", "onetrust", "cookieconsent", "cookie-law",
        "complianz", "osano", "termly", "cookie-notice", "cmplz",
        "cookie-consent", "didomi", "usercentrics", "quantcast",
    )

    trackers = (
        "googletagmanager", "google-analytics", "gtag(", "fbq(",
        "connect.facebook.net", "hotjar", "clarity.ms",
    )

    if any(t in html for t in trackers) and not any(c in html for c in consent_tools):

        issues.append(_issue(
            "Medium", "Tracking Without Cookie Consent Banner",
            "Analytics/advertising scripts are present but no cookie "
            "consent tool was detected.",
            "Add a consent manager that blocks trackers until the visitor agrees.",
        ))

    # ---------- credibility ----------

    if not has_link("facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "youtube.com"):

        issues.append(_issue(
            "Info", "No Social Profile Links",
            "No links to social profiles were found.",
            "Link active social profiles to build credibility.",
        ))

    if not any(
        k in html for k in ("testimonial", "review", "recension", "trustpilot", "rating", "clienti")
    ):

        issues.append(_issue(
            "Info", "No Social Proof Detected",
            "No testimonials, reviews or ratings were detected.",
            "Add customer testimonials, logos or review widgets.",
        ))

    return issues
