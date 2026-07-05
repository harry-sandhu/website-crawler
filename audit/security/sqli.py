from .models import SecurityIssue


class SQLInjectionTester:

    def __init__(self):

        self.risky_parameters = {

            "id",
            "user",
            "userid",
            "username",
            "account",
            "customer",
            "client",
            "email",
            "search",
            "query",
            "q",
            "filter",
            "keyword",
            "sort",
            "order",
            "page",

        }

        self.input_types = {

            "text",
            "search",
            "email",
            "password",
            "textarea",
            "hidden",
            "number",

        }

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        for form in report.forms:

            for field in form.fields:

                field_type = (
                    field.field_type or ""
                ).lower()

                if field_type not in self.input_types:
                    continue

                severity = "Low"
                confidence = "Low"

                if (
                    field.name
                    and field.name.lower() in self.risky_parameters
                ):

                    severity = "Medium"
                    confidence = "Medium"

                report.issues.append(

                    SecurityIssue(

                        severity=severity,

                        title="Potential SQL Injection Entry Point",

                        category="SQL Injection",

                        description=(
                            f"The input field '{field.name}' accepts user-controlled "
                            "data and could influence backend database queries if "
                            "server-side protections are missing."
                        ),

                        recommendation=(
                            "Use parameterized queries or prepared statements, "
                            "validate all server-side input, avoid dynamic SQL "
                            "construction, and enforce least-privilege database "
                            "permissions."
                        ),

                        endpoint=form.action,

                        parameter=field.name,

                        evidence=(
                            f"Input type: {field_type}"
                        ),

                        impact=(
                            "Improper handling of database input may expose or "
                            "modify sensitive information."
                        ),

                        confidence=confidence,

                        cwe="CWE-89",

                        owasp="A03:2021 - Injection",

                        fix_time="2-8 hours",

                    )

                )

                if not field.pattern:

                    report.issues.append(

                        SecurityIssue(

                            severity="Low",

                            title="Database Input Missing Client Validation",

                            category="SQL Injection",

                            description=(
                                f"The field '{field.name}' does not define a "
                                "client-side validation pattern."
                            ),

                            recommendation=(
                                "Implement appropriate client-side validation for "
                                "usability, but always enforce strict validation "
                                "and sanitization on the server."
                            ),

                            endpoint=form.action,

                            parameter=field.name,

                            evidence="No HTML pattern attribute found.",

                            impact=(
                                "Client-side validation alone is not a security "
                                "control, but missing validation can increase "
                                "invalid input reaching the server."
                            ),

                            confidence="Low",

                            cwe="CWE-20",

                            owasp="A03:2021 - Injection",

                            fix_time="30-60 minutes",

                        )

                    )