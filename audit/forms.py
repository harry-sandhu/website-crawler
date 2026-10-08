from urllib.parse import urljoin, urlparse

from audit.models import Issue

CATEGORY = "Forms"


def _issue(severity, title, description, recommendation, evidence="", selector=""):

    return Issue(
        category=CATEGORY,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        evidence=evidence,
        selector=selector,
        confidence="High",
        verification_method="Markup inspection",
    )


def run_form_audit(website):

    issues = []

    soup = website.page["soup"]
    page_url = website.url

    for index, form in enumerate(soup.find_all("form"), start=1):

        fields = [
            i for i in form.find_all(["input", "textarea", "select"])
            if i.get("type") not in ("hidden", "submit", "button", "image", "reset")
        ]

        if not fields:
            continue

        name = form.get("id") or form.get("class") and ".".join(form.get("class")[:2]) or f"form#{index}"
        selector = f"form:{name}"
        types = {(f.get("type") or f.name).lower() for f in fields}
        is_login = "password" in types
        has_email = "email" in types or any(
            "email" in (f.get("name") or "").lower() for f in fields
        )

        # ---------- submit control ----------

        if not form.find(["button"]) and not form.find("input", type=["submit", "image"]):

            issues.append(_issue(
                "Medium", "Form Has No Submit Button",
                f"{name} has no visible submit control.",
                "Add a <button type=submit> so users can send the form.",
                selector=selector,
            ))

        # ---------- labels ----------

        unlabeled = []

        for field in fields:

            fid = field.get("id")
            labelled = (
                field.get("aria-label")
                or field.get("aria-labelledby")
                or field.find_parent("label")
                or (fid and form.find("label", attrs={"for": fid}))
                or (fid and soup.find("label", attrs={"for": fid}))
            )

            if not labelled:
                unlabeled.append(field.get("name") or field.get("placeholder") or field.name)

        if unlabeled:

            issues.append(_issue(
                "Medium", "Form Fields Without Labels",
                f"{len(unlabeled)} fields in {name} have no label "
                "(placeholders vanish when typing).",
                "Associate a visible <label> with every field.",
                evidence=", ".join(unlabeled[:8]),
                selector=selector,
            ))

        # ---------- input types ----------

        wrong = []

        for field in fields:

            fname = (field.get("name") or field.get("id") or "").lower()
            ftype = (field.get("type") or "text").lower()

            if "mail" in fname and ftype != "email":
                wrong.append(f"{fname} should be type=email")

            if any(k in fname for k in ("phone", "tel", "telefono")) and ftype != "tel":
                wrong.append(f"{fname} should be type=tel")

        if wrong:

            issues.append(_issue(
                "Low", "Wrong Input Types",
                "Fields use generic text inputs where specialised types "
                "give mobile users the right keyboard and validation.",
                "Use type=email, tel, number, etc.",
                evidence="\n".join(wrong[:8]),
                selector=selector,
            ))

        # ---------- required fields ----------

        if not is_login and not any(f.has_attr("required") for f in fields):

            issues.append(_issue(
                "Low", "No Required Fields Marked",
                f"{name} has no required fields, so empty submissions are possible.",
                "Mark essential fields as required and validate server-side.",
                selector=selector,
            ))

        # ---------- transport ----------

        action = urljoin(page_url, form.get("action") or "")

        if page_url.startswith("https") and action.startswith("http://"):

            issues.append(_issue(
                "High", "Form Submits Over HTTP",
                f"{name} posts to an insecure URL.",
                "Submit forms to https:// endpoints only.",
                evidence=action,
                selector=selector,
            ))

        # ---------- spam protection / consent ----------

        text = form.get_text(" ", strip=True).lower()
        html = str(form).lower()

        spam_guard = any(
            k in html for k in (
                "captcha", "recaptcha", "hcaptcha", "turnstile", "honeypot",
                "g-recaptcha", "cf-turnstile",
            )
        )

        if has_email and not is_login and not spam_guard:

            issues.append(_issue(
                "Low", "Contact Form Without Spam Protection",
                f"{name} has no CAPTCHA/honeypot, so bots can flood it.",
                "Add a honeypot field, Turnstile or reCAPTCHA.",
                selector=selector,
            ))

        if has_email and not is_login and not any(
            k in text for k in ("privacy", "consent", "gdpr", "informativa", "acconsento")
        ) and not form.find("input", type="checkbox"):

            issues.append(_issue(
                "Medium", "Form Collects Data Without Privacy Consent",
                f"{name} collects personal data with no consent checkbox or "
                "privacy notice (required under GDPR).",
                "Add a consent checkbox linking to the privacy policy.",
                selector=selector,
            ))

    return issues
