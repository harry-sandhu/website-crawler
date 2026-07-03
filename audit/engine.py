from audit.report import AuditReport

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.security import run_security_audit
from audit.responsive import run_responsive_audit
from audit.accessibility import run_accessibility_audit
from audit.lighthouse import run_lighthouse_audit


class AuditEngine:

    def __init__(self):

        self.audit_modules = [

            # ----------------------------------
            # SEO
            # ----------------------------------

            lambda website: run_seo_audit(
                website.page
            ),

            # ----------------------------------
            # Network
            # ----------------------------------

            lambda website: run_network_audit(
                website.browser
            ),

            # ----------------------------------
            # Console
            # ----------------------------------

            lambda website: run_console_audit(
                website.browser
            ),

            # ----------------------------------
            # Security
            # ----------------------------------

            lambda website: run_security_audit(
                website
            ),

            # ----------------------------------
            # Responsive
            # ----------------------------------

            lambda website: run_responsive_audit(
                website.page_object,
                website.screenshot_manager,
            ),

            # ----------------------------------
            # Accessibility (axe-core)
            # ----------------------------------

            lambda website: run_accessibility_audit(
                website.page_object,
            ),

            # ----------------------------------
            # Lighthouse
            # ----------------------------------

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