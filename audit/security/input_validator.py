from .models import SecurityIssue
from .shared import (
    is_framework_token_name,
    looks_sensitive_token_name,
    looks_sensitive_token_value,
)


class InputValidator:

    def __init__(self):

        pass

    # ----------------------------------

    def _form_key(self, form):

        parts = [
            form.id,
            form.name,
            form.action,
            form.method,
            form.url,
        ]

        return "|".join(
            str(part or "").strip().lower()
            for part in parts
            if str(part or "").strip()
        ) or "form"

    def _field_label(self, field):

        return (
            field.name
            or field.field_type
            or "field"
        )

    def _title_family(self, title):

        lower = (title or "").lower()

        families = (
            ("password managers may be disabled", "password-autocomplete"),
            ("password field autocomplete disabled", "password-autocomplete"),
            ("password autocomplete", "password-autocomplete"),
            ("weak password policy", "password-policy"),
            ("password field missing minimum length", "password-policy"),
            ("autocomplete", "autocomplete"),
            ("pattern", "pattern"),
            ("minimum length", "minlength"),
            ("maxlength", "maxlength"),
            ("maximum length", "maxlength"),
            ("placeholder", "placeholder"),
            ("optional input field", "optional"),
            ("missing name", "missing-name"),
            ("unnamed input field", "missing-name"),
            ("number field", "number-limits"),
            ("hidden field contains default value", "hidden-default"),
            ("sensitive hidden field", "hidden-sensitive"),
            ("readonly", "readonly-disabled"),
            ("disabled", "readonly-disabled"),
            ("file upload", "file-upload"),
            ("password", "password"),
            ("token", "token"),
            ("secret", "secret"),
            ("auth", "auth"),
        )

        for needle, family in families:

            if needle in lower:
                return family

        return lower.replace(" ", "-") or "finding"

    def _normalized_category(self, category, title):

        lower = (title or "").lower()

        if "password" in lower:
            return "Authentication"

        if any(
            token in lower
            for token in (
                "autocomplete",
                "pattern",
                "maxlength",
                "minimum length",
                "maximum length",
                "placeholder",
                "missing name",
                "unnamed input",
                "optional input",
                "number field",
                "hidden field contains default value",
                "readonly",
                "disabled",
            )
        ):
            return "HTML Best Practices"

        if any(
            token in lower
            for token in (
                "login",
                "register",
                "reset",
                "mfa",
                "oauth",
                "sso",
            )
        ):
            return "Authentication"

        if any(
            token in lower
            for token in (
                "secret",
                "sensitive",
                "file validation",
                "token",
            )
        ):
            return "Security"

        return category or "Input Validation"

    def _normalized_severity(self, severity, title):

        lower = (title or "").lower()

        overrides = (
            ("missing h1 heading", "Medium"),
            ("hidden field contains default value", "Info"),
            ("optional input field", "Info"),
            ("autocomplete", "Info"),
            ("placeholder missing", "Info"),
            ("missing pattern", "Low"),
            ("missing maxlength", "Low"),
            ("missing minlength", "Low"),
            ("number field missing step value", "Info"),
            ("readonly", "Info"),
            ("disabled", "Info"),
            ("password field missing minimum length", "Medium"),
            ("weak password policy inferred", "Medium"),
            ("password autocomplete", "Info"),
            ("sensitive hidden field detected", "Medium"),
            ("sensitive field name detected", "Medium"),
            ("server-side file validation required", "Medium"),
        )

        for needle, mapped in overrides:
            if needle in lower:
                return mapped

        if (
            severity == "Info"
            and self._normalized_category(
                "",
                title,
            ) == "Security"
        ):
            return "Low"

        return severity or "Info"

    def _merge_issue(self, existing, incoming):

        existing.occurrences += max(
            1,
            int(
                getattr(
                    incoming,
                    "occurrences",
                    1,
                )
                or 1
            ),
        )

        for item in getattr(
            incoming,
            "affected_items",
            [],
        ):
            if item and item not in existing.affected_items:
                existing.affected_items.append(
                    item
                )

        if incoming.evidence:

            evidence_lines = []

            for value in (
                existing.evidence,
                incoming.evidence,
            ):

                for line in str(value or "").splitlines():

                    line = line.strip()

                    if line and line not in evidence_lines:
                        evidence_lines.append(line)

            existing.evidence = "\n".join(
                evidence_lines[:8]
            )

        if getattr(
            incoming,
            "verification",
            "",
        ) == "Confirmed":

            existing.verification = "Confirmed"


    def report_issue(
        self,
        report,
        severity,
        title,
        description,
        recommendation,
        form,
        field,
        evidence="",
        confidence="Low",
        impact="",
        cwe="CWE-20",
        owasp="A05:2021 - Security Misconfiguration",
        fix_time="15-30 minutes",
        category="Input Validation",
        finding_key="",
        affected_item="",
        selector="",
        page="",
        verification_method="",
        occurrences=1,
    ):

        resolved_category = self._normalized_category(
            category,
            title,
        )

        resolved_severity = self._normalized_severity(
            severity,
            title,
        )

        form_key = self._form_key(
            form,
        )

        resolved_selector = selector or f"form:{form_key}"

        resolved_page = page or form.url or ""

        resolved_finding_key = finding_key or "|".join(
            [
                resolved_category,
                form_key,
                self._title_family(title),
            ]
        )

        resolved_affected_item = (
            affected_item
            or self._field_label(field)
        )

        issue = SecurityIssue(
            severity=resolved_severity,
            title=title,
            category=resolved_category,
            description=description,
            recommendation=recommendation,
            endpoint=form.action,
            page=resolved_page,
            selector=resolved_selector,
            parameter=field.name,
            evidence=evidence,
            confidence=confidence,
            impact=impact,
            cwe=cwe,
            owasp=owasp,
            fix_time=fix_time,
            finding_key=resolved_finding_key,
            affected_item=resolved_affected_item,
            affected_items=[
                resolved_affected_item
            ]
            if resolved_affected_item
            else [],
            occurrences=max(
                1,
                int(occurrences or 1),
            ),
            verification_method=verification_method or "Form field inspection",
        )

        for existing in report.issues:

            if getattr(
                existing,
                "finding_key",
                "",
            ) == resolved_finding_key:

                self._merge_issue(
                    existing,
                    issue,
                )

                return

        report.issues.append(
            issue
        )
    


    def check_hidden(
        self,
        report,
        form,
        field,
    ):
        name = (field.name or "").lower()
        value = field.value or ""

        framework_hidden_names = {
            "action",
            "csrf",
            "csrf_token",
            "module",
            "token",
            "fc",
            "form_token",
            "_token",
        }

        if name in framework_hidden_names or is_framework_token_name(name):
            return

        business_logic_hints = (
            "price",
            "fee",
            "amount",
            "total",
            "subtotal",
            "discount",
            "tax",
            "shipping",
            "quantity",
            "qty",
            "role",
            "permission",
            "account",
            "user",
            "order",
            "id",
        )

        if looks_sensitive_token_name(name) or looks_sensitive_token_value(value):

            self.report_issue(
                report,
                "High",
                "Sensitive Hidden Field Detected",
                (
                    f"Hidden field '{field.name}' appears to hold sensitive "
                    "material."
                ),
                (
                    "Do not trust hidden form fields for security decisions. "
                    "Validate and recalculate sensitive values on the server."
                ),
                form,
                field,
                evidence=(
                    "Sensitive token-like name or value detected in a hidden field."
                ),
                confidence="HIGH_CONFIDENCE",
                impact=(
                    "Client-side hidden values can be modified before submission."
                ),
                cwe="CWE-602",
                owasp="A01:2021 - Broken Access Control",
                fix_time="30-60 minutes",
                category="Security",
                verification_method="Hidden field inspection",
            )

            return

        if any(
            hint in name
            for hint in business_logic_hints
        ):

            self.report_issue(
                report,
                "Medium",
                "Hidden Business Logic Field Detected",
                (
                    f"Hidden field '{field.name}' appears to influence business "
                    "logic or pricing."
                ),
                (
                    "Recalculate business logic on the server and do not trust "
                    "hidden fields for pricing, roles, or identifiers."
                ),
                form,
                field,
                evidence=f"Hidden field name: {field.name}; value: {field.value}",
                confidence="NEEDS_MANUAL_REVIEW",
                impact=(
                    "Hidden business logic fields can be tampered with in the browser."
                ),
                cwe="CWE-602",
                owasp="A04:2021 - Insecure Design",
                fix_time="30-60 minutes",
                category="Business Logic",
                verification_method="Hidden field inspection",
            )

    def check_number(
        self,
        report,
        form,
        field,
    ):
    
        if not field.min:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Number Field Missing Minimum Value",
    
                (
                    f"Number field '{field.name}' does not define a minimum value."
                ),
    
                (
                    "Specify an appropriate minimum value and enforce it on the server."
                ),
    
                form,
    
                field,
    
                evidence="Missing min attribute.",
    
            )
    
        if not field.max:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Number Field Missing Maximum Value",
    
                (
                    f"Number field '{field.name}' does not define a maximum value."
                ),
    
                (
                    "Specify an appropriate maximum value and validate it server-side."
                ),
    
                form,
    
                field,
    
                evidence="Missing max attribute.",
    
            )
    
        if not field.step:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Number Field Missing Step Value",
    
                (
                    f"Number field '{field.name}' does not define a step value."
                ),
    
                (
                    "Specify a step value when only certain increments are valid."
                ),
    
                form,
    
                field,
    
                evidence="Missing step attribute.",
    
                fix_time="5 minutes",
    
            )


    def check_phone(
        self,
        report,
        form,
        field,
    ):
    
        if not field.pattern:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Phone Field Missing Pattern Validation",
    
                (
                    f"Phone field '{field.name}' does not define "
                    "an HTML validation pattern."
                ),
    
                (
                    "Validate phone numbers using an appropriate pattern "
                    "and always perform server-side validation."
                ),
    
                form,
    
                field,
    
                evidence="Missing pattern attribute.",
    
            )
    
        if field.maxlength is None:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Phone Field Missing Maximum Length",
    
                (
                    f"Phone field '{field.name}' does not define a maximum length."
                ),
    
                (
                    "Specify a reasonable maximum length to improve validation."
                ),
    
                form,
    
                field,
    
                evidence="No maxlength attribute.",
    
                fix_time="5 minutes",
    
            )
    
        if field.autocomplete != "tel":
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Phone Autocomplete Not Configured",
    
                (
                    f"Phone field '{field.name}' is missing "
                    "autocomplete='tel'."
                ),
    
                (
                    "Use autocomplete='tel' to improve browser autofill support."
                ),
    
                form,
    
                field,
    
                evidence=f"autocomplete='{field.autocomplete}'",
    
                fix_time="5 minutes",
    
            )        

    def check_email(
        self,
        report,
        form,
        field,
    ):
    
        if not field.pattern:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Email Field Missing Pattern Validation",
    
                (
                    f"Email field '{field.name}' does not define "
                    "an HTML validation pattern."
                ),
    
                (
                    "Validate email addresses on both the client "
                    "and the server."
                ),
    
                form,
    
                field,
    
                evidence="Missing pattern attribute.",
    
                cwe="CWE-20",
    
                owasp="A05:2021 - Security Misconfiguration",
    
            )
    
        if field.maxlength is None:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Email Field Missing Maximum Length",
    
                (
                    f"Email field '{field.name}' has no maximum length."
                ),
    
                (
                    "Define a reasonable maximum length and "
                    "enforce it on the server."
                ),
    
                form,
    
                field,
    
                evidence="No maxlength attribute.",
    
            )
    
        if field.autocomplete != "email":
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Email Autocomplete Not Configured",
    
                (
                    f"Email field '{field.name}' is missing "
                    "autocomplete='email'."
                ),
    
                (
                    "Enable autocomplete to improve usability "
                    "and password manager support."
                ),
    
                form,
    
                field,
    
                evidence=f"autocomplete='{field.autocomplete}'",
    
                fix_time="5 minutes",
    
            )

    
    def check_file(
        self,
        report,
        form,
        field,
    ):
    
        if not field.accept:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "File Upload Accepts Any File Type",
    
                (
                    f"File upload field '{field.name}' does not specify "
                    "an accepted file type."
                ),
    
                (
                    "Restrict selectable file types using the HTML "
                    "'accept' attribute and always validate file type "
                    "and content on the server."
                ),
    
                form,
    
                field,
    
                evidence="Missing accept attribute.",
    
                confidence="Medium",
    
                impact=(
                    "Users may attempt to upload unexpected file types."
                ),
    
                cwe="CWE-434",
    
                owasp="A05:2021 - Security Misconfiguration",
    
                fix_time="10-20 minutes",
    
            )
    
        if field.multiple:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Multiple File Upload Enabled",
    
                (
                    f"File upload field '{field.name}' allows multiple files."
                ),
    
                (
                    "Ensure every uploaded file is independently validated "
                    "for type, size, malware, and content."
                ),
    
                form,
    
                field,
    
                evidence="multiple=true",
    
                confidence="Low",
    
                impact=(
                    "Multiple uploads increase validation complexity."
                ),
    
                cwe="CWE-434",
    
                owasp="A05:2021 - Security Misconfiguration",
    
                fix_time="15 minutes",
    
            )
    
        self.report_issue(
    
            report,
    
            "Info",
    
            "Server-side File Validation Required",
    
            (
                f"File upload field '{field.name}' requires server-side validation."
            ),
    
            (
                "Never rely on client-side restrictions. Validate MIME type, "
                "file signature, extension, size, storage location, and scan "
                "uploaded files before processing."
            ),
    
            form,
    
            field,
    
            evidence="File upload field detected.",
    
            confidence="High",
    
            impact=(
                "Improper file validation can lead to malicious file uploads."
            ),
    
            cwe="CWE-434",
    
            owasp="A05:2021 - Security Misconfiguration",
    
            fix_time="1-2 hours",
    
        )


    def check_text(
        self,
        report,
        form,
        field,
    ):
    
        if not field.name:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "Unnamed Input Field",
    
                (
                    "A text input does not define a name attribute."
                ),
    
                (
                    "Ensure every form field has a unique name so "
                    "validation and processing are predictable."
                ),
    
                form,
    
                field,
    
                evidence="Missing name attribute.",
    
                confidence="High",
    
                cwe="CWE-20",
    
            )
    
        if field.maxlength is None:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Text Field Missing Maximum Length",
    
                (
                    f"Text field '{field.name}' does not define "
                    "a maximum length."
                ),
    
                (
                    "Define a reasonable maximum length and "
                    "validate it server-side."
                ),
    
                form,
    
                field,
    
                evidence="No maxlength attribute.",
    
            )
    
        elif field.maxlength > 500:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Very Large Maximum Length",
    
                (
                    f"Text field '{field.name}' allows "
                    f"{field.maxlength} characters."
                ),
    
                (
                    "Review whether such a large value is required."
                ),
    
                form,
    
                field,
    
                evidence=f"maxlength={field.maxlength}",
    
            )
    
        if not field.autocomplete:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Autocomplete Not Configured",
    
                (
                    f"Text field '{field.name}' does not define "
                    "an autocomplete attribute."
                ),
    
                (
                    "Configure autocomplete where appropriate."
                ),
    
                form,
    
                field,
    
                evidence="Missing autocomplete attribute.",
    
                fix_time="5 minutes",
    
            )
    
        if not field.placeholder:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Placeholder Missing",
    
                (
                    f"Text field '{field.name}' has no placeholder."
                ),
    
                (
                    "Consider adding a placeholder to improve usability."
                ),
    
                form,
    
                field,
    
                evidence="Missing placeholder.",
    
                fix_time="5 minutes",
    
            )
    
        if field.readonly:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Readonly Text Field",
    
                (
                    f"Text field '{field.name}' is readonly."
                ),
    
                (
                    "Readonly fields can still be modified using "
                    "browser developer tools. Never trust client-side restrictions."
                ),
    
                form,
    
                field,
    
                evidence="readonly=true",
    
                cwe="CWE-602",
    
            )
    
        if field.disabled:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Disabled Text Field",
    
                (
                    f"Text field '{field.name}' is disabled."
                ),
    
                (
                    "Disabled fields are not submitted by browsers. "
                    "Ensure server-side logic does not rely on them."
                ),
    
                form,
    
                field,
    
                evidence="disabled=true",
    
                cwe="CWE-602",
    
            )   


    def check_common(
        self,
        report,
        form,
        field,
    ):
        name = (field.name or "").lower()
    
        # ----------------------------------
        # Missing Name
        # ----------------------------------
    
        if not field.name:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "Form Field Missing Name",
    
                (
                    "A form field is missing a name attribute."
                ),
    
                (
                    "Assign a unique name to every form field."
                ),
    
                form,
    
                field,
    
                evidence="Missing name attribute.",
    
                confidence="High",
    
                cwe="CWE-20",
    
                fix_time="5 minutes",
    
            )
    
        # ----------------------------------
        # Optional Field
        # ----------------------------------
    
        if not field.required:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Optional Input Field",
    
                (
                    f"Field '{field.name}' is optional."
                ),
    
                (
                    "Verify this field is intentionally optional."
                ),
    
                form,
    
                field,
    
                evidence="required=false",
    
                fix_time="2 minutes",
    
            )
    
        # ----------------------------------
        # Suspicious Field Names
        # ----------------------------------
    
        if looks_sensitive_token_name(name):

            self.report_issue(

                report,

                "Info",

                "Sensitive Field Name Detected",

                (
                    f"Field '{field.name}' appears to contain "
                    "security-related information."
                ),

                (
                    "Ensure sensitive values are never trusted "
                    "solely because they originate from the client."
                ),

                form,

                field,

                evidence="Name suggests a secret or credential.",

                confidence="Medium",

                impact=(
                    "Client-side values can be modified before submission."
                ),

                cwe="CWE-602",

                owasp="A01:2021 - Broken Access Control",

                fix_time="10 minutes",

                category="Security",

            )
    
        # ----------------------------------
        # Readonly
        # ----------------------------------
    
        if field.readonly:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Readonly Field Detected",
    
                (
                    f"Field '{field.name}' is marked readonly."
                ),
    
                (
                    "Readonly fields can be modified using browser "
                    "developer tools. Validate values on the server."
                ),
    
                form,
    
                field,
    
                evidence="readonly=true",
    
                cwe="CWE-602",
    
            )
    
        # ----------------------------------
        # Disabled
        # ----------------------------------
    
        if field.disabled:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Disabled Field Detected",
    
                (
                    f"Field '{field.name}' is disabled."
                ),
    
                (
                    "Disabled fields are not submitted by browsers. "
                    "Ensure server-side logic does not rely on them."
                ),
    
                form,
    
                field,
    
                evidence="disabled=true",
    
                cwe="CWE-602",
    
            )         

    def check_password(
        self,
        report,
        form,
        field,
    ):
    
        if field.minlength is None:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "Password Field Missing Minimum Length",
    
                (
                    f"Password field '{field.name}' does not specify a minimum length."
                ),
    
                (
                    "Require a minimum password length of at least 8-12 characters."
                ),
    
                form,
    
                field,
    
                evidence="No minlength attribute.",
    
                confidence="Medium",
    
                cwe="CWE-521",
    
                owasp="A07:2021 - Identification and Authentication Failures",
    
                fix_time="10 minutes",
    
            )
    
        elif field.minlength < 8:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "Weak Password Length Policy",
    
                (
                    f"Password field '{field.name}' allows passwords shorter than 8 characters."
                ),
    
                (
                    "Increase the minimum password length to at least 8 characters."
                ),
    
                form,
    
                field,
    
                evidence=f"minlength={field.minlength}",
    
                confidence="High",
    
                cwe="CWE-521",
    
                owasp="A07:2021 - Identification and Authentication Failures",
    
                fix_time="10 minutes",
    
            )
    
        if field.autocomplete == "on":
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Password Autocomplete Enabled",
    
                (
                    f"Password field '{field.name}' explicitly enables autocomplete."
                ),
    
                (
                    "Review whether this behavior is intentional."
                ),
    
                form,
    
                field,
    
                evidence="autocomplete='on'",
    
                fix_time="5 minutes",
    
            )
    
        if not field.autocomplete:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Password Autocomplete Not Specified",
    
                (
                    f"Password field '{field.name}' does not specify an autocomplete attribute."
                ),
    
                (
                    "Use autocomplete='current-password' or "
                    "autocomplete='new-password' as appropriate."
                ),
    
                form,
    
                field,
    
                evidence="Missing autocomplete attribute.",
    
                fix_time="5 minutes",
    
            )
    
        if field.readonly:
    
            self.report_issue(
    
                report,
    
                "Medium",
    
                "Password Field Is Readonly",
    
                (
                    "Readonly fields can still be modified using browser developer tools."
                ),
    
                (
                    "Never rely on readonly fields for security decisions."
                ),
    
                form,
    
                field,
    
                evidence="readonly=true",
    
                confidence="Medium",
    
            )
    
        if field.disabled:
    
            self.report_issue(
    
                report,
    
                "Low",
    
                "Password Field Is Disabled",
    
                (
                    "Disabled inputs are not submitted by browsers."
                ),
    
                (
                    "Ensure authentication does not depend on disabled client-side fields."
                ),
    
                form,
    
                field,
    
                evidence="disabled=true",
    
            )       

    def run(
        self,
        website,
        report,
    ):
    
        for form in report.forms:
    
            for field in form.fields:
    
                field_type = (
                    field.field_type
                    .lower()
                    .strip()
                )
    
                # --------------------------
                # Email
                # --------------------------
    
                if field_type == "email":
    
                    self.check_email(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Password
                # --------------------------
    
                elif field_type == "password":
    
                    self.check_password(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Number
                # --------------------------
    
                elif field_type == "number":
    
                    self.check_number(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Phone
                # --------------------------
    
                elif field_type == "tel":
    
                    self.check_phone(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Hidden
                # --------------------------
    
                elif field_type == "hidden":
    
                    self.check_hidden(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # File Upload
                # --------------------------
    
                elif field_type == "file":
    
                    self.check_file(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Generic Text Inputs
                # --------------------------
    
                elif field_type in {
    
                    "text",
    
                    "search",
    
                    "url",
    
                    "textarea",
    
                }:
    
                    self.check_text(
                        report,
                        form,
                        field,
                    )
    
                # --------------------------
                # Common Checks
                # --------------------------
    
                self.check_common(
                    report,
                    form,
                    field,
                )
