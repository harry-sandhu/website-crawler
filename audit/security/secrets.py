import re

from .models import SecurityIssue
from .shared import text_snippet


class SecretsTester:

    PATTERNS = [
        (
            "AWS Access Key ID Exposed",
            "High",
            re.compile(
                r"\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})\b"
            ),
            "AWS access key material was observed in content.",
            "Remove embedded AWS credentials and rotate the key pair.",
            "CWE-798",
        ),
        (
            "Google API Key Exposed",
            "Medium",
            re.compile(
                r"\bAIza[0-9A-Za-z\-_]{35}\b"
            ),
            "A Google API key was observed in content.",
            "Restrict the key by origin, API, and usage where possible.",
            "CWE-200",
        ),
        (
            "Stripe Publishable Key Exposed",
            "Info",
            re.compile(
                r"\bpk_(?:live|test)_[0-9A-Za-z]{16,}\b"
            ),
            "A Stripe publishable key was observed in content.",
            "Verify that only publishable keys are exposed client-side.",
            "CWE-200",
        ),
        (
            "Stripe Secret Key Exposed",
            "High",
            re.compile(
                r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"
            ),
            "A Stripe secret key was observed in content.",
            "Remove the secret key from client-visible code and rotate it.",
            "CWE-798",
        ),
        (
            "GitHub Token Exposed",
            "High",
            re.compile(
                r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"
            ),
            "A GitHub token was observed in content.",
            "Remove the token from the page or script and rotate it.",
            "CWE-798",
        ),
        (
            "GitHub Fine-Grained Token Exposed",
            "High",
            re.compile(
                r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"
            ),
            "A GitHub fine-grained token was observed in content.",
            "Remove the token from the page or script and rotate it.",
            "CWE-798",
        ),
        (
            "Bearer Token Exposed",
            "High",
            re.compile(
                r"\bBearer\s+[A-Za-z0-9\-._~+/=]{20,}\b",
                re.IGNORECASE,
            ),
            "A bearer token was observed in content.",
            "Avoid embedding bearer tokens in HTML or JavaScript.",
            "CWE-798",
        ),
        (
            "Webhook URL Exposed",
            "Medium",
            re.compile(
                r"https?://(?:hooks\.slack\.com/services/[A-Za-z0-9/_-]+|"
                r"discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_-]+|"
                r"outlook\.office\.com/webhook/[A-Za-z0-9/_-]+|"
                r"hooks\.zapier\.com/hooks/catch/[A-Za-z0-9/_-]+)"
            ),
            "A webhook endpoint was observed in content.",
            "Move webhook URLs out of client-visible code or lock them down.",
            "CWE-200",
        ),
        (
            "Private Key Block Exposed",
            "Critical",
            re.compile(
                r"-----BEGIN [A-Z0-9 ]+ PRIVATE KEY-----"
            ),
            "A private key block was observed in content.",
            "Remove the private key from the application and rotate it.",
            "CWE-321",
        ),
        (
            "JWT-Like Token Exposed",
            "Low",
            re.compile(
                r"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
            "A JWT-like token was observed in content.",
            "Review whether the token should be exposed to the browser.",
            "CWE-200",
        ),
    ]

    def _add_issue(
        self,
        report,
        **kwargs,
    ):

        report.issues.append(
            SecurityIssue(
                **kwargs,
            )
        )

    def _sources(
        self,
        website,
        report,
    ):

        page = website.page or {}

        sources = [
            page.get("html", "") or "",
        ]

        for key in ("scripts", "stylesheets", "links", "buttons", "emails", "phones"):

            value = page.get(
                key,
                [],
            )

            if isinstance(value, list):

                for item in value:

                    if isinstance(item, dict):

                        sources.extend(
                            [
                                item.get("href", ""),
                                item.get("src", ""),
                                item.get("text", ""),
                                item.get("action", ""),
                            ]
                        )

                    else:

                        sources.append(
                            str(item)
                        )

        for request in report.requests:

            for header_name, header_value in (request.response_headers or {}).items():

                sources.append(
                    f"{header_name}: {header_value}"
                )

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        for key in (
            "cookies",
            "local_storage",
            "session_storage",
            "storage",
        ):

            value = browser.get(key)

            if isinstance(value, dict):

                for item_key, item_value in value.items():

                    sources.extend(
                        [
                            str(item_key),
                            str(item_value),
                        ]
                    )

            elif isinstance(value, list):

                for item in value:

                    sources.append(
                        str(item)
                    )

            elif value:

                sources.append(
                    str(value)
                )

        return sources

    def _report_match(
        self,
        report,
        website,
        title,
        severity,
        evidence,
        description,
        recommendation,
        cwe,
    ):

        primary_request = report.requests[0] if report.requests else None

        self._add_issue(
            report,
            severity=severity,
            title=title,
            category="Secrets",
            description=description,
            recommendation=recommendation,
            endpoint=website.url,
            page=website.url,
            response_code=(
                primary_request.response_status
                if primary_request
                else None
            ),
            evidence=text_snippet(
                evidence,
                220,
            ),
            confidence="High",
            impact=(
                "Secret material in client-visible content can be copied, "
                "reused, or abused."
            ),
            cwe=cwe,
            owasp="A05:2021 - Security Misconfiguration",
            fix_time="5 minutes",
        )

    def _firebase_hint(
        self,
        source,
    ):

        lower = source.lower()

        hints = (
            "firebaseconfig",
            "initializeapp(",
            "firebase.initializeapp",
            "apikey",
            "authdomain",
            "projectid",
            "storagebucket",
            "messagingsenderid",
            "appid",
        )

        return sum(
            1
            for hint in hints
            if hint in lower
        ) >= 3

    def run(
        self,
        website,
        report,
    ):

        seen = set()

        for source in self._sources(
            website,
            report,
        ):

            if not source:
                continue

            if self._firebase_hint(
                source
            ):

                evidence = "Firebase configuration markers were observed."

                if evidence not in seen:

                    seen.add(
                        evidence
                    )

                    self._report_match(
                        report,
                        website,
                        "Firebase Configuration Exposed",
                        "Low",
                        source,
                        "Firebase configuration details appear to be present in client-visible content.",
                        "Move Firebase configuration management behind build-time controls and keep secrets out of public code.",
                        "CWE-200",
                    )

            for title, severity, pattern, description, recommendation, cwe in self.PATTERNS:

                for match in pattern.finditer(
                    source
                ):

                    evidence = match.group(
                        0
                    )

                    key = (
                        title,
                        evidence,
                    )

                    if key in seen:
                        continue

                    seen.add(
                        key
                    )

                    self._report_match(
                        report,
                        website,
                        title,
                        severity,
                        evidence,
                        description,
                        recommendation,
                        cwe,
                    )

