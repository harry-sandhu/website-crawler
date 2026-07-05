from .models import SecurityIssue
from .shared import header_value, normalize_headers, text_snippet


class HeadersTester:

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

    def _primary_request(
        self,
        website,
        report,
    ):

        if not report.requests:
            return None

        target = (
            website.url or ""
        ).rstrip("/")

        for request in report.requests:

            if (
                (request.url or "").rstrip("/")
                == target
            ):
                return request

        for request in report.requests:

            content_type = header_value(
                request.response_headers,
                "content-type",
            ).lower()

            if "text/html" in content_type:
                return request

        return report.requests[0]

    def _meta_csp(
        self,
        soup,
    ):

        if not soup:
            return ""

        for meta in soup.find_all("meta"):

            http_equiv = (
                meta.get("http-equiv")
                or ""
            ).lower()

            if http_equiv == "content-security-policy":

                return meta.get("content") or ""

        return ""

    def _check_hsts(
        self,
        report,
        request,
        headers,
        website,
    ):

        target_url = (
            request.url
            or website.url
            or ""
        ).lower()

        if not target_url.startswith("https://"):
            return

        value = header_value(
            headers,
            "strict-transport-security",
        )

        if not value:

            self._add_issue(
                report,
                severity="High",
                title="Missing Strict-Transport-Security Header",
                category="Headers",
                description=(
                    "The HTTPS response does not send an HSTS header."
                ),
                recommendation=(
                    "Add Strict-Transport-Security with a long max-age, "
                    "includeSubDomains where appropriate, and preload "
                    "after confirming the domain is ready."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence="Strict-Transport-Security header missing.",
                impact=(
                    "Browsers cannot enforce HTTPS-only access for future "
                    "requests to this site."
                ),
                confidence="High",
                cwe="CWE-319",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="10 minutes",
            )

            return

        lower = value.lower()

        weak = []

        max_age = 0

        for part in lower.split(";"):

            part = part.strip()

            if part.startswith("max-age="):

                try:

                    max_age = int(
                        part.split("=", 1)[1].strip()
                    )

                except Exception:

                    weak.append("invalid max-age")

        if max_age and max_age < 31536000:

            weak.append("short max-age")

        if max_age and "includesubdomains" not in lower:

            weak.append("missing includeSubDomains")

        if weak:

            self._add_issue(
                report,
                severity="Medium",
                title="Weak Strict-Transport-Security Header",
                category="Headers",
                description=(
                    "The HSTS policy is present but not as strong as it "
                    "could be."
                ),
                recommendation=(
                    "Use a long max-age, includeSubDomains when safe, and "
                    "consider preload after validating all subdomains."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=(
                    f"HSTS value: {text_snippet(value)}"
                ),
                notes=", ".join(weak),
                impact=(
                    "Weak HSTS settings reduce protection against HTTPS "
                    "downgrade and cookie interception attacks."
                ),
                confidence="High",
                cwe="CWE-319",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="15 minutes",
            )

    def _check_csp(
        self,
        report,
        request,
        headers,
        soup,
        website,
    ):

        value = header_value(
            headers,
            "content-security-policy",
        )

        meta_value = self._meta_csp(
            soup,
        )

        if not value and not meta_value:

            self._add_issue(
                report,
                severity="Medium",
                title="Missing Content-Security-Policy Header",
                category="Headers",
                description=(
                    "No Content-Security-Policy header or meta policy was "
                    "observed."
                ),
                recommendation=(
                    "Deploy a restrictive Content-Security-Policy and "
                    "tune it for the application's real resource usage."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence="No CSP header or meta policy detected.",
                impact=(
                    "Without CSP, reflected content and script injection "
                    "risks are harder to contain."
                ),
                confidence="High",
                cwe="CWE-693",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="30 minutes",
            )

            return

        if not value and meta_value:

            self._add_issue(
                report,
                severity="Low",
                title="Content-Security-Policy Delivered via Meta Tag",
                category="Headers",
                description=(
                    "A CSP was found in a meta tag instead of an HTTP "
                    "response header."
                ),
                recommendation=(
                    "Prefer sending Content-Security-Policy as an HTTP "
                    "header so it is enforced earlier and more reliably."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=text_snippet(meta_value),
                confidence="Medium",
                impact=(
                    "Meta-delivered policies are easier to bypass than "
                    "response headers in some scenarios."
                ),
                cwe="CWE-693",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="15 minutes",
            )

            value = meta_value

        lower = value.lower()

        weak = []

        for token in ("unsafe-inline", "unsafe-eval", "*", "data:"):

            if token in lower:
                weak.append(token)

        if weak:

            self._add_issue(
                report,
                severity="Medium",
                title="Weak Content-Security-Policy",
                category="Headers",
                description=(
                    "The Content-Security-Policy contains permissive "
                    "sources or execution directives."
                ),
                recommendation=(
                    "Remove unsafe directives where possible and narrow the "
                    "allowlist to the minimum required sources."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=(
                    f"CSP value: {text_snippet(value)}"
                ),
                notes=", ".join(sorted(set(weak))),
                impact=(
                    "A permissive CSP reduces the protection against script "
                    "injection and data exfiltration."
                ),
                confidence="High",
                cwe="CWE-693",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="30 minutes",
            )

    def _check_xfo(
        self,
        report,
        request,
        headers,
        website,
    ):

        value = header_value(
            headers,
            "x-frame-options",
        )

        if not value:

            self._add_issue(
                report,
                severity="Medium",
                title="Missing X-Frame-Options Header",
                category="Headers",
                description=(
                    "The response does not send an X-Frame-Options header."
                ),
                recommendation=(
                    "Use X-Frame-Options or a CSP frame-ancestors directive "
                    "to prevent clickjacking."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence="X-Frame-Options header missing.",
                impact=(
                    "The page may be embedded in hostile frames."
                ),
                confidence="High",
                cwe="CWE-1021",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

            return

        if value.upper() not in {"DENY", "SAMEORIGIN"}:

            self._add_issue(
                report,
                severity="Low",
                title="Weak X-Frame-Options Header",
                category="Headers",
                description=(
                    "The X-Frame-Options header is not set to a strong "
                    "anti-framing value."
                ),
                recommendation=(
                    "Prefer DENY or SAMEORIGIN, or use CSP frame-ancestors."
                ),
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=f"X-Frame-Options value: {value}",
                confidence="High",
                impact="Weak framing protection may allow clickjacking.",
                cwe="CWE-1021",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

    def _check_expected_value(
        self,
        report,
        request,
        headers,
        website,
        header_name,
        expected_values,
        title,
        missing_severity,
        weak_severity,
        missing_description,
        missing_recommendation,
        weak_description,
        weak_recommendation,
        cwe,
    ):

        value = header_value(
            headers,
            header_name,
        )

        if not value:

            self._add_issue(
                report,
                severity=missing_severity,
                title=f"Missing {title}",
                category="Headers",
                description=missing_description,
                recommendation=missing_recommendation,
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=f"{title} header missing.",
                confidence="High",
                impact=(
                    f"The site is missing the {title} protection header."
                ),
                cwe=cwe,
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

            return

        lower = value.lower()

        if not expected_values:

            if "*" in lower:

                self._add_issue(
                    report,
                    severity=weak_severity,
                    title=f"Weak {title}",
                    category="Headers",
                    description=weak_description,
                    recommendation=weak_recommendation,
                    endpoint=request.url,
                    page=website.url,
                    response_code=request.response_status,
                    evidence=(
                        f"{title} value: {text_snippet(value)}"
                    ),
                    confidence="High",
                    impact=(
                        f"The {title} header is present but appears overly permissive."
                    ),
                    cwe=cwe,
                    owasp="A05:2021 - Security Misconfiguration",
                    fix_time="5 minutes",
                )

            return

        if not any(
            expected in lower
            for expected in expected_values
        ):

            self._add_issue(
                report,
                severity=weak_severity,
                title=f"Weak {title}",
                category="Headers",
                description=weak_description,
                recommendation=weak_recommendation,
                endpoint=request.url,
                page=website.url,
                response_code=request.response_status,
                evidence=(
                    f"{title} value: {text_snippet(value)}"
                ),
                confidence="High",
                impact=(
                    f"The {title} header is present but not strongly configured."
                ),
                cwe=cwe,
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

    def run(
        self,
        website,
        report,
    ):

        request = self._primary_request(
            website,
            report,
        )

        if not request:
            return

        headers = normalize_headers(
            request.response_headers
        )

        soup = website.page.get(
            "soup"
        )

        self._check_hsts(
            report,
            request,
            headers,
            website,
        )

        self._check_csp(
            report,
            request,
            headers,
            soup,
            website,
        )

        self._check_xfo(
            report,
            request,
            headers,
            website,
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "x-content-type-options",
            {"nosniff"},
            "X-Content-Type-Options Header",
            "Low",
            "Low",
            "The response does not include X-Content-Type-Options.",
            "Set X-Content-Type-Options to nosniff.",
            "The header is present but does not use nosniff.",
            "Use X-Content-Type-Options: nosniff.",
            "CWE-693",
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "referrer-policy",
            {
                "no-referrer",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
            },
            "Referrer-Policy Header",
            "Low",
            "Low",
            "The response does not define a Referrer-Policy header.",
            "Set a Referrer-Policy that matches the site's privacy needs.",
            "The header value is more permissive than recommended.",
            "Choose a stricter Referrer-Policy such as same-origin.",
            "CWE-693",
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "permissions-policy",
            set(),
            "Permissions-Policy Header",
            "Low",
            "Low",
            "The response does not define a Permissions-Policy header.",
            "Add a Permissions-Policy header to disable features the site "
            "does not need.",
            "The Permissions-Policy header appears overly permissive.",
            "Restrict powerful browser features to the minimum required.",
            "CWE-693",
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "cross-origin-opener-policy",
            {
                "same-origin",
                "same-origin-allow-popups",
            },
            "Cross-Origin-Opener-Policy Header",
            "Low",
            "Low",
            "The response does not define a Cross-Origin-Opener-Policy header.",
            "Set Cross-Origin-Opener-Policy to same-origin where possible.",
            "The Cross-Origin-Opener-Policy value is weaker than expected.",
            "Use same-origin or same-origin-allow-popups.",
            "CWE-693",
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "cross-origin-embedder-policy",
            {
                "require-corp",
                "credentialless",
            },
            "Cross-Origin-Embedder-Policy Header",
            "Low",
            "Low",
            "The response does not define a Cross-Origin-Embedder-Policy header.",
            "Set Cross-Origin-Embedder-Policy only if the application is ready for it.",
            "The Cross-Origin-Embedder-Policy value is weaker than expected.",
            "Use require-corp or credentialless if cross-origin isolation is needed.",
            "CWE-693",
        )

        self._check_expected_value(
            report,
            request,
            headers,
            website,
            "cross-origin-resource-policy",
            {
                "same-origin",
                "same-site",
            },
            "Cross-Origin-Resource-Policy Header",
            "Low",
            "Low",
            "The response does not define a Cross-Origin-Resource-Policy header.",
            "Set Cross-Origin-Resource-Policy to same-origin or same-site where appropriate.",
            "The Cross-Origin-Resource-Policy value is weaker than expected.",
            "Use same-origin or same-site to limit cross-origin exposure.",
            "CWE-693",
        )
