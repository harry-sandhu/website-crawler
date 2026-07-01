from audit.report import AuditReport

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.security import run_security_audit

from audit.responsive import run_responsive_audit
from browser.screenshots import ScreenshotManager


class AuditEngine:
    def __init__(self):
        self.audit_modules = [
            lambda website, page: run_seo_audit(website.page),
            lambda website, page: run_network_audit(website.browser),
            lambda website, page: run_console_audit(website.browser),
            lambda website, page: run_security_audit(website),
            lambda website, page: run_responsive_audit(
                page,
                ScreenshotManager(),
            ),
        ]

    def run(self, website, page):
        report = AuditReport()

        for module in self.audit_modules:
            try:
                report.issues.extend(
                    module(
                        website,
                        page,
                    )
                )
            except Exception as e:
                print(f"[Audit Error] {module}: {e}")

        return report