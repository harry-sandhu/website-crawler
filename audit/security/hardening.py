"""CORS, HTTP methods, subresource integrity and email-spoofing checks."""

import shutil
import subprocess
from urllib.parse import urlparse

import requests

from .models import SecurityIssue

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebsiteAuditor/2.0)"}


def _issue(report, severity, title, description, recommendation, **kwargs):

    kwargs.setdefault("owasp", "A05:2021 Security Misconfiguration")

    report.issues.append(SecurityIssue(
        severity=severity,
        title=title,
        category="Security",
        description=description,
        recommendation=recommendation,
        confidence="High",
        **kwargs,
    ))


# ----------------------------------
# CORS
# ----------------------------------

class CORSTester:

    def run(self, website, report):

        evil = "https://evil.example"

        try:
            response = requests.get(
                website.url,
                headers={**HEADERS, "Origin": evil},
                timeout=10,
            )
        except requests.RequestException:
            return

        allow = response.headers.get("access-control-allow-origin", "")
        creds = response.headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow == evil and creds:

            _issue(
                report, "High", "CORS Reflects Arbitrary Origin With Credentials",
                "The server echoes any Origin and allows credentials, so "
                "any website can read authenticated responses.",
                "Validate Origin against an allowlist; never combine "
                "credentials with reflected origins.",
                evidence=f"Origin: {evil} -> ACAO: {allow}, credentials: true",
                verification="Confirmed",
                verification_method="Crafted Origin header request",
                cwe="CWE-942",
                finding_key="cors|reflected-credentials",
            )

        elif allow == evil:

            _issue(
                report, "Low", "CORS Reflects Arbitrary Origin",
                "The server echoes any Origin in Access-Control-Allow-Origin.",
                "Restrict allowed origins to a fixed allowlist.",
                evidence=f"Origin: {evil} -> ACAO: {allow}",
                verification="Confirmed",
                verification_method="Crafted Origin header request",
                cwe="CWE-942",
                finding_key="cors|reflected",
            )

        elif allow == "null" and creds:

            _issue(
                report, "High", "CORS Allows null Origin With Credentials",
                "Sandboxed documents can read authenticated responses.",
                "Remove 'null' from the allowed origins.",
                cwe="CWE-942",
                finding_key="cors|null",
            )


# ----------------------------------
# HTTP methods
# ----------------------------------

class HTTPMethodsTester:

    RISKY = {"TRACE", "TRACK", "PUT", "DELETE", "CONNECT", "PATCH"}

    def run(self, website, report):

        try:
            response = requests.options(website.url, headers=HEADERS, timeout=10)
        except requests.RequestException:
            return

        allow = {
            m.strip().upper()
            for m in response.headers.get("allow", "").split(",") if m.strip()
        }

        risky = sorted(allow & self.RISKY)

        if risky:

            _issue(
                report, "Medium" if {"TRACE", "TRACK"} & set(risky) else "Low",
                "Risky HTTP Methods Advertised",
                f"The server advertises: {', '.join(risky)}.",
                "Disable methods the site does not need.",
                evidence=response.headers.get("allow", ""),
                verification="Confirmed",
                verification_method="OPTIONS request",
                cwe="CWE-749",
                finding_key="methods|risky",
            )


# ----------------------------------
# Subresource integrity
# ----------------------------------

class SRITester:

    def run(self, website, report):

        host = urlparse(website.url).netloc.replace("www.", "")
        soup = website.page["soup"]
        missing = []

        for tag in soup.find_all(["script", "link"]):

            url = tag.get("src") or (
                tag.get("href") if "stylesheet" in (tag.get("rel") or []) else None
            )

            if not url or not url.startswith(("http://", "https://", "//")):
                continue

            if host in url or tag.get("integrity"):
                continue

            missing.append(url)

        if missing:

            _issue(
                report, "Low", "Third-Party Resources Without Subresource Integrity",
                f"{len(missing)} external scripts/styles load without an "
                "integrity hash; a compromised CDN could inject code.",
                "Add integrity and crossorigin attributes, or self-host.",
                evidence="\n".join(missing[:10]),
                affected_items=missing[:10],
                verification="Confirmed",
                verification_method="Markup inspection",
                cwe="CWE-353",
                owasp="A08:2021 Software and Data Integrity Failures",
                finding_key="sri|missing",
            )


# ----------------------------------
# Email spoofing (SPF / DMARC)
# ----------------------------------

class EmailSecurityTester:

    def _txt(self, name):

        try:
            import dns.resolver
            return [
                b"".join(r.strings).decode("utf-8", "ignore")
                for r in dns.resolver.resolve(name, "TXT", lifetime=6)
            ]
        except ImportError:
            pass
        except Exception:
            return []

        dig = shutil.which("dig")

        if not dig:
            return None

        try:
            out = subprocess.run(
                [dig, "+short", "TXT", name],
                capture_output=True, text=True, timeout=8,
            ).stdout
        except Exception:
            return []

        return [line.strip().strip('"') for line in out.splitlines() if line.strip()]

    def run(self, website, report):

        host = urlparse(website.url).netloc.split(":")[0]
        domain = host[4:] if host.startswith("www.") else host

        spf_records = self._txt(domain)

        if spf_records is None:
            return  # no resolver available; skip silently

        spf = [r for r in spf_records if r.lower().startswith("v=spf1")]

        if not spf:

            _issue(
                report, "Medium", "Missing SPF Record",
                f"{domain} publishes no SPF record, so anyone can forge email "
                "from this domain more easily.",
                "Publish an SPF TXT record listing authorised senders, "
                "ending in -all or ~all.",
                verification="Confirmed",
                verification_method="DNS TXT lookup",
                cwe="CWE-290",
                finding_key="email|spf-missing",
            )

        elif spf[0].rstrip().endswith("+all") or " ?all" in spf[0]:

            _issue(
                report, "High", "Permissive SPF Policy",
                "The SPF record allows any server to send mail.",
                "Use -all or ~all.",
                evidence=spf[0],
                verification="Confirmed",
                verification_method="DNS TXT lookup",
                cwe="CWE-290",
                finding_key="email|spf-permissive",
            )

        dmarc = [
            r for r in (self._txt(f"_dmarc.{domain}") or [])
            if r.lower().startswith("v=dmarc1")
        ]

        if not dmarc:

            _issue(
                report, "Medium", "Missing DMARC Record",
                f"{domain} has no DMARC policy, enabling email spoofing and "
                "phishing in the company's name.",
                "Publish a _dmarc TXT record, start with p=none and move to "
                "quarantine/reject.",
                verification="Confirmed",
                verification_method="DNS TXT lookup",
                cwe="CWE-290",
                finding_key="email|dmarc-missing",
            )

        elif "p=none" in dmarc[0].lower().replace(" ", ""):

            _issue(
                report, "Low", "DMARC Policy Not Enforced",
                "DMARC is set to p=none (monitor only).",
                "Move to p=quarantine or p=reject once reports look clean.",
                evidence=dmarc[0],
                verification="Confirmed",
                verification_method="DNS TXT lookup",
                cwe="CWE-290",
                finding_key="email|dmarc-none",
            )
