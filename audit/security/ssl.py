from datetime import datetime, timezone

from .models import SecurityIssue
from .shared import header_value, normalize_headers, text_snippet


class SSLTester:

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

        return report.requests[0]

    def _has_title(
        self,
        report,
        title,
    ):

        return any(
            issue.title == title
            for issue in report.issues
        )

    def _page_resources(
        self,
        website,
    ):

        page = website.page or {}

        resources = []

        for key in ("images", "links", "scripts", "stylesheets", "forms"):

            for item in page.get(key, []):

                if isinstance(item, dict):

                    resources.extend(
                        [
                            item.get("src", ""),
                            item.get("href", ""),
                            item.get("action", ""),
                        ]
                    )

                else:

                    resources.append(
                        str(item)
                    )

        for form in getattr(
            website,
            "forms",
            [],
        ):

            resources.append(
                getattr(form, "action", "")
            )

        return [
            resource
            for resource in resources
            if resource
        ]

    def _check_https(
        self,
        report,
        website,
        primary_request,
    ):

        target_url = (
            primary_request.url
            or website.url
            or ""
        ).lower()

        if target_url.startswith("https://"):
            return

        self._add_issue(
            report,
            severity="High",
            title="Site Does Not Use HTTPS",
            category="SSL",
            description=(
                "The primary site URL is served over HTTP instead of HTTPS."
            ),
            recommendation=(
                "Serve the site over HTTPS and redirect all HTTP traffic "
                "to the secure endpoint."
            ),
            endpoint=primary_request.url,
            page=website.url,
            response_code=primary_request.response_status,
            evidence=(
                f"Primary URL: {website.url}"
            ),
            impact=(
                "Unencrypted traffic can expose credentials, cookies, and "
                "page content to interception."
            ),
            confidence="High",
            cwe="CWE-319",
            owasp="A02:2021 - Cryptographic Failures",
            fix_time="30 minutes",
        )

    def _check_redirects(
        self,
        report,
        website,
    ):

        if not (
            website.url or ""
        ).lower().startswith("http://"):
            return

        redirected = False

        for request in report.requests:

            headers = normalize_headers(
                request.response_headers
            )

            location = header_value(
                headers,
                "location",
            )

            if (
                request.response_status in (301, 302, 307, 308)
                and location.lower().startswith("https://")
            ):
                redirected = True
                break

            if (
                (request.url or "").lower().startswith("https://")
                and request.response_status in (200, 204)
            ):
                redirected = True
                break

        if redirected:

            self._add_issue(
                report,
                severity="Info",
                title="HTTP to HTTPS Redirect Observed",
                category="SSL",
                description=(
                    "The site appears to redirect from HTTP to HTTPS."
                ),
                recommendation=(
                    "Keep redirect behavior in place and pair it with HSTS "
                    "for better downgrade protection."
                ),
                endpoint=website.url,
                page=website.url,
                evidence=(
                    "An HTTPS destination or redirect was observed."
                ),
                impact=(
                    "Redirects help, but they do not fully replace HSTS."
                ),
                confidence="High",
                cwe="CWE-319",
                owasp="A02:2021 - Cryptographic Failures",
                fix_time="5 minutes",
            )

    def _check_mixed_content(
        self,
        report,
        website,
    ):

        if not (
            website.url or ""
        ).lower().startswith("https://"):
            return

        mixed = []

        for resource in self._page_resources(
            website,
        ):

            if str(resource).lower().startswith("http://"):
                mixed.append(
                    resource
                )

        if mixed:

            self._add_issue(
                report,
                severity="High",
                title="Mixed Content Detected",
                category="SSL",
                description=(
                    "The HTTPS page references insecure HTTP resources."
                ),
                recommendation=(
                    "Serve all subresources over HTTPS or remove the "
                    "mixed-content references."
                ),
                endpoint=website.url,
                page=website.url,
                evidence="\n".join(
                    mixed[:20]
                ),
                impact=(
                    "Insecure subresources weaken the guarantees provided by "
                    "HTTPS and can be tampered with in transit."
                ),
                confidence="High",
                cwe="CWE-319",
                owasp="A02:2021 - Cryptographic Failures",
                fix_time="30 minutes",
            )

    def _check_hsts(
        self,
        report,
        website,
        primary_request,
    ):

        if self._has_title(
            report,
            "Missing Strict-Transport-Security Header",
        ) or self._has_title(
            report,
            "Weak Strict-Transport-Security Header",
        ):
            return

        if not (
            website.url or ""
        ).lower().startswith("https://"):
            return

        headers = normalize_headers(
            primary_request.response_headers
        )

        value = header_value(
            headers,
            "strict-transport-security",
        )

        if value:
            return

        self._add_issue(
            report,
            severity="High",
            title="HTTPS Site Missing HSTS",
            category="SSL",
            description=(
                "The HTTPS site does not send an HSTS header."
            ),
            recommendation=(
                "Enable HSTS with a long max-age after confirming the "
                "site is fully ready for HTTPS-only operation."
            ),
            endpoint=primary_request.url,
            page=website.url,
            response_code=primary_request.response_status,
            evidence="Strict-Transport-Security header missing.",
            impact=(
                "Without HSTS, browsers may continue to allow downgrade "
                "attempts on future visits."
            ),
            confidence="High",
            cwe="CWE-319",
            owasp="A02:2021 - Cryptographic Failures",
            fix_time="10 minutes",
        )

    def _check_certificate(
        self,
        report,
        website,
    ):

        browser = getattr(
            website,
            "browser",
            {},
        ) or {}

        certificate = (
            browser.get("certificate")
            or browser.get("cert")
            or browser.get("tls_certificate")
            or {}
        )

        tls = (
            browser.get("tls")
            or browser.get("security")
            or browser.get("ssl")
            or {}
        )

        if isinstance(certificate, str):

            certificate = {
                "subject": certificate,
            }

        if isinstance(tls, str):

            tls = {
                "version": tls,
            }

        tls_version = (
            tls.get("version")
            or tls.get("protocol")
            or tls.get("tls_version")
            or ""
        )

        cipher = (
            tls.get("cipher")
            or tls.get("cipher_suite")
            or ""
        )

        if tls_version:

            lower = str(tls_version).lower()

            if any(
                token in lower
                for token in (
                    "sslv3",
                    "tlsv1.0",
                    "tlsv1.1",
                    "tls 1.0",
                    "tls 1.1",
                )
            ):

                self._add_issue(
                    report,
                    severity="Medium",
                    title="Weak TLS Version Observed",
                    category="SSL",
                    description=(
                        "The site appears to use an older TLS protocol."
                    ),
                    recommendation=(
                        "Disable legacy TLS versions and prefer TLS 1.2 or "
                        "TLS 1.3."
                    ),
                    endpoint=website.url,
                    page=website.url,
                    evidence=f"TLS version: {tls_version}",
                    impact=(
                        "Older TLS versions are more likely to use weaker "
                        "ciphers and allow downgrade issues."
                    ),
                    confidence="Medium",
                    cwe="CWE-327",
                    owasp="A02:2021 - Cryptographic Failures",
                    fix_time="30 minutes",
                )

        if cipher:

            weak_ciphers = (
                "rc4",
                "3des",
                "des ",
                "null",
                "export",
                "md5",
            )

            lower = str(cipher).lower()

            if any(
                token in lower
                for token in weak_ciphers
            ):

                self._add_issue(
                    report,
                    severity="Medium",
                    title="Weak TLS Cipher Observed",
                    category="SSL",
                    description=(
                        "The observed TLS cipher suite appears to be weak."
                    ),
                    recommendation=(
                        "Prefer modern AEAD cipher suites and disable weak "
                        "legacy ciphers."
                    ),
                    endpoint=website.url,
                    page=website.url,
                    evidence=f"Cipher suite: {cipher}",
                    impact=(
                        "Weak ciphers can reduce the confidentiality and "
                        "integrity of encrypted traffic."
                    ),
                    confidence="Medium",
                    cwe="CWE-327",
                    owasp="A02:2021 - Cryptographic Failures",
                    fix_time="30 minutes",
                )

        certificate_text = " ".join(
            str(certificate.get(key, ""))
            for key in (
                "subject",
                "issuer",
                "not_before",
                "not_after",
                "expires",
                "valid_to",
            )
        ).strip()

        if certificate_text:

            self._add_issue(
                report,
                severity="Info",
                title="TLS Certificate Information Observed",
                category="SSL",
                description=(
                    "Certificate metadata was available from the browser."
                ),
                recommendation=(
                    "Review certificate subject, issuer, and expiry as part "
                    "of operational hygiene."
                ),
                endpoint=website.url,
                page=website.url,
                evidence=text_snippet(certificate_text, 220),
                confidence="Low",
                impact=(
                    "Certificate metadata can help verify the site's "
                    "deployment posture."
                ),
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

        expires = (
            certificate.get("not_after")
            or certificate.get("expires")
            or certificate.get("valid_to")
        )

        if expires:

            expiry_text = str(expires)

            try:

                expiry_dt = datetime.fromisoformat(
                    expiry_text.replace("Z", "+00:00")
                )

            except Exception:

                expiry_dt = None

            if expiry_dt and expiry_dt.tzinfo is None:

                expiry_dt = expiry_dt.replace(
                    tzinfo=timezone.utc,
                )

            if expiry_dt:

                days = (
                    expiry_dt
                    - datetime.now(timezone.utc)
                ).total_seconds() / 86400

                if days <= 30:

                    self._add_issue(
                        report,
                        severity="Medium",
                        title="TLS Certificate Expires Soon",
                        category="SSL",
                        description=(
                            "The observed certificate appears to expire soon."
                        ),
                        recommendation=(
                            "Renew the certificate before it expires and keep "
                            "monitoring in place."
                        ),
                        endpoint=website.url,
                        page=website.url,
                        evidence=f"Certificate expires in {days:.1f} days.",
                        confidence="Medium",
                        impact=(
                            "Expired certificates can break HTTPS access and "
                            "reduce user trust."
                        ),
                        cwe="CWE-298",
                        owasp="A02:2021 - Cryptographic Failures",
                        fix_time="5 minutes",
                    )

    def run(
        self,
        website,
        report,
    ):

        primary_request = self._primary_request(
            website,
            report,
        )

        if not primary_request:
            return

        self._check_https(
            report,
            website,
            primary_request,
        )

        self._check_redirects(
            report,
            website,
        )

        self._check_mixed_content(
            report,
            website,
        )

        self._check_hsts(
            report,
            website,
            primary_request,
        )

        self._check_certificate(
            report,
            website,
        )
