from audit.report import AuditReport

from audit.seo import run_seo_audit
from audit.network import run_network_audit
from audit.console import run_console_audit
from audit.security import run_security_audit


class AuditEngine:
    def __init__(self):
        self.audit_modules = [
            lambda website: run_seo_audit(website.page),
            lambda website: run_network_audit(website.browser),
            lambda website: run_console_audit(website.browser),
            lambda website: run_security_audit(website),
        ]

    def run(self, website):
        report = AuditReport()

        for module in self.audit_modules:
            try:
                report.issues.extend(module(website))
            except Exception as e:
                print(f"[Audit Error] {module}: {e}")

        return report