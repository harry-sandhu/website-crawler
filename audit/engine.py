from audit.report import AuditReport

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.security import run_security_audit
from audit.responsive import run_responsive_audit
from audit.lighthouse import run_lighthouse_audit


class AuditEngine:

    def __init__(self):

        self.audit_modules = [

            lambda website: run_seo_audit(
                website.page
            ),

            lambda website: run_network_audit(
                website.browser
            ),

            lambda website: run_console_audit(
                website.browser
            ),

            lambda website: run_security_audit(
                website
            ),

            lambda website: run_responsive_audit(
                website.page_object,
                website.screenshot_manager,
            ),

            lambda website: run_lighthouse_audit(
                website.url
            ),

        ]

    def run(self, website):

        report = AuditReport()

        for module in self.audit_modules:

            try:

                report.issues.extend(
                    module(website)
                )

            except Exception as e:

                print(f"[Audit Error] {module}: {e}")

        return report