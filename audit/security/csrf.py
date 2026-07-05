from .models import SecurityIssue


class CSRFTester:

    def run(
        self,
        website,
        report,
    ):

        for form in report.forms:

            method = (
                form.method or ""
            ).upper()

            if method != "POST":

                continue

            token_found = False

            for field in form.fields:

                name = (
                    field.name or ""
                ).lower()

                if any(

                    keyword in name

                    for keyword in (

                        "csrf",

                        "token",

                        "_token",

                        "authenticity",

                        "__requestverificationtoken",

                    )

                ):

                    token_found = True

                    break

            if not token_found:

                report.issues.append(

                    SecurityIssue(

                        severity="High",

                        title="Potential Missing CSRF Protection",

                        category="CSRF",

                        description=(
                            "POST form does not appear to include "
                            "an anti-CSRF token."
                        ),

                        recommendation=(
                            "Use unpredictable anti-CSRF tokens and "
                            "validate them on the server."
                        ),

                        endpoint=form.action,

                        evidence="No CSRF token field detected.",

                        impact=(
                            "This is a heuristic indicator and should be "
                            "verified against real request handling."
                        ),

                        confidence="NEEDS_MANUAL_REVIEW",

                        cwe="CWE-352",

                        owasp="A01 Broken Access Control",

                        fix_time="2-4 hours",

                        verification_method="Form token inspection",

                    )

                )
