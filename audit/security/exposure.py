"""Sensitive file and directory exposure checks.

Every finding is verified against a content signature, so sites that answer
200 for every URL (soft 404) do not produce false positives.
"""

import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

import requests

from .models import SecurityIssue

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; WebsiteAuditor/2.0)"}

SECRET_ENV = re.compile(
    r"^\s*[A-Z][A-Z0-9_]*(PASSWORD|SECRET|KEY|TOKEN|DB_|DATABASE_URL)[A-Z0-9_]*\s*=",
    re.M,
)

# path, severity, title, matcher(bytes_text, content_type) -> bool, cwe
CHECKS = [
    ("/.git/HEAD", "Critical", "Exposed Git Repository",
     lambda t, c: t.startswith("ref:"), "CWE-538"),
    ("/.git/config", "Critical", "Exposed Git Configuration",
     lambda t, c: "[core]" in t, "CWE-538"),
    ("/.env", "Critical", "Exposed Environment File",
     lambda t, c: bool(SECRET_ENV.search(t)), "CWE-538"),
    ("/.env.local", "Critical", "Exposed Environment File",
     lambda t, c: bool(SECRET_ENV.search(t)), "CWE-538"),
    ("/.env.production", "Critical", "Exposed Environment File",
     lambda t, c: bool(SECRET_ENV.search(t)), "CWE-538"),
    ("/wp-config.php.bak", "Critical", "Exposed WordPress Config Backup",
     lambda t, c: "DB_PASSWORD" in t, "CWE-530"),
    ("/wp-config.php~", "Critical", "Exposed WordPress Config Backup",
     lambda t, c: "DB_PASSWORD" in t, "CWE-530"),
    ("/wp-config.php.old", "Critical", "Exposed WordPress Config Backup",
     lambda t, c: "DB_PASSWORD" in t, "CWE-530"),
    ("/config.php.bak", "Critical", "Exposed Config Backup",
     lambda t, c: any(k in t.lower() for k in ("password", "db_pass", "secret")), "CWE-530"),
    ("/backup.sql", "Critical", "Exposed Database Dump",
     lambda t, c: any(k in t for k in ("CREATE TABLE", "INSERT INTO", "mysqldump")), "CWE-530"),
    ("/database.sql", "Critical", "Exposed Database Dump",
     lambda t, c: any(k in t for k in ("CREATE TABLE", "INSERT INTO", "mysqldump")), "CWE-530"),
    ("/dump.sql", "Critical", "Exposed Database Dump",
     lambda t, c: any(k in t for k in ("CREATE TABLE", "INSERT INTO", "mysqldump")), "CWE-530"),
    ("/backup.zip", "High", "Exposed Backup Archive",
     lambda t, c: t.startswith("PK") or "zip" in c, "CWE-530"),
    ("/site.zip", "High", "Exposed Backup Archive",
     lambda t, c: t.startswith("PK") or "zip" in c, "CWE-530"),
    ("/.svn/entries", "High", "Exposed SVN Metadata",
     lambda t, c: bool(re.match(r"^\d+\s", t)) or "dir" in t[:50], "CWE-538"),
    ("/.DS_Store", "Low", "Exposed .DS_Store File",
     lambda t, c: "Bud1" in t[:16], "CWE-538"),
    ("/.htpasswd", "High", "Exposed .htpasswd File",
     lambda t, c: bool(re.search(r"^\w+:\$?\w+", t, re.M)) and "<html" not in t.lower(), "CWE-538"),
    ("/phpinfo.php", "Medium", "Exposed phpinfo()",
     lambda t, c: "PHP Version" in t and "phpinfo" in t.lower(), "CWE-200"),
    ("/info.php", "Medium", "Exposed phpinfo()",
     lambda t, c: "PHP Version" in t and "phpinfo" in t.lower(), "CWE-200"),
    ("/server-status", "Medium", "Exposed Apache Server Status",
     lambda t, c: "Apache Server Status" in t, "CWE-200"),
    ("/server-info", "Medium", "Exposed Apache Server Info",
     lambda t, c: "Apache Server Information" in t, "CWE-200"),
    ("/phpmyadmin/", "Medium", "phpMyAdmin Publicly Reachable",
     lambda t, c: "phpMyAdmin" in t, "CWE-284"),
    ("/adminer.php", "High", "Adminer Database Tool Reachable",
     lambda t, c: "Adminer" in t, "CWE-284"),
    ("/composer.json", "Low", "Exposed composer.json",
     lambda t, c: '"require"' in t, "CWE-200"),
    ("/package.json", "Low", "Exposed package.json",
     lambda t, c: '"dependencies"' in t or '"scripts"' in t, "CWE-200"),
    ("/web.config", "Medium", "Exposed web.config",
     lambda t, c: "<configuration" in t, "CWE-538"),
    ("/actuator/env", "Critical", "Exposed Spring Actuator Environment",
     lambda t, c: "propertySources" in t, "CWE-200"),
    ("/actuator/heapdump", "Critical", "Exposed Spring Heap Dump",
     lambda t, c: "JAVA PROFILE" in t[:30], "CWE-200"),
    ("/wp-json/wp/v2/users", "Medium", "WordPress User Enumeration",
     lambda t, c: '"slug"' in t and t.lstrip().startswith("["), "CWE-203"),
    ("/xmlrpc.php", "Low", "WordPress XML-RPC Enabled",
     lambda t, c: "XML-RPC server accepts POST requests only" in t, "CWE-307"),
    ("/swagger.json", "Low", "Public API Specification",
     lambda t, c: '"swagger"' in t or '"openapi"' in t, "CWE-200"),
    ("/openapi.json", "Low", "Public API Specification",
     lambda t, c: '"openapi"' in t, "CWE-200"),
    ("/id_rsa", "Critical", "Exposed Private SSH Key",
     lambda t, c: "PRIVATE KEY" in t, "CWE-321"),
]

LISTING_PATHS = [
    "/uploads/", "/wp-content/uploads/", "/images/", "/img/", "/assets/",
    "/files/", "/backup/", "/backups/", "/logs/", "/tmp/", "/admin/",
]


class ExposureTester:

    def _get(self, url):

        try:

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=8,
                allow_redirects=False,
                stream=True,
            )

            body = next(response.iter_content(8192), b"") if response.status_code == 200 else b""
            response.close()

            return response.status_code, body.decode("utf-8", "ignore"), (
                response.headers.get("content-type", "").lower()
            )

        except requests.RequestException:

            return None, "", ""

    def _probe(self, args):

        base, check = args
        path, severity, title, matcher, cwe = check
        url = urljoin(base, path)
        status, text, ctype = self._get(url)

        if status == 200 and text:

            try:
                matched = matcher(text, ctype)
            except Exception:
                matched = False

            if matched:
                return url, severity, title, cwe, text[:120].replace("\n", " ")

        return None

    def _listing(self, args):

        base, path = args
        url = urljoin(base, path)
        status, text, _ = self._get(url)

        if status == 200 and re.search(r"<title>\s*Index of /", text, re.I):
            return url

        return None

    def run(self, website, report):

        base = website.url

        with ThreadPoolExecutor(max_workers=10) as pool:

            hits = [
                h for h in pool.map(self._probe, [(base, c) for c in CHECKS]) if h
            ]

            listings = [
                u for u in pool.map(self._listing, [(base, p) for p in LISTING_PATHS]) if u
            ]

        seen = set()

        for url, severity, title, cwe, snippet in hits:

            if (title, url) in seen:
                continue

            seen.add((title, url))

            report.issues.append(SecurityIssue(
                severity=severity,
                title=title,
                category="Security",
                description=f"{url} is publicly accessible and matches the "
                            "expected file signature.",
                recommendation="Remove the file from the web root or block "
                               "access at the web server. Rotate any "
                               "credentials it contained.",
                endpoint=url,
                evidence=snippet if severity != "Critical" else "(content withheld; signature matched)",
                verification="Confirmed",
                verification_method="HTTP fetch verification",
                confidence="High",
                cwe=cwe,
                owasp="A05:2021 Security Misconfiguration",
                finding_key=f"exposure|{url}",
                affected_item=url,
                fix_time="15 minutes",
            ))

        if listings:

            report.issues.append(SecurityIssue(
                severity="Medium",
                title="Directory Listing Enabled",
                category="Security",
                description=f"{len(listings)} directories list their contents.",
                recommendation="Disable directory indexing (Options -Indexes / autoindex off).",
                evidence="\n".join(listings),
                affected_items=listings,
                verification="Confirmed",
                verification_method="HTTP fetch verification",
                confidence="High",
                cwe="CWE-548",
                owasp="A05:2021 Security Misconfiguration",
                finding_key="exposure|directory-listing",
            ))
