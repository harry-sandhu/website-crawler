from .models import SecurityIssue


class InputValidator:

    def __init__(self):

        pass

    # ----------------------------------


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
    
    ):
    
        report.issues.append(
    
            SecurityIssue(
    
                severity=severity,
    
                title=title,
    
                category="Input Validation",
    
                description=description,
    
                recommendation=recommendation,
    
                endpoint=form.action,
    
                parameter=field.name,
    
                evidence=evidence,
    
                confidence=confidence,
    
                impact=impact,
    
                cwe=cwe,
    
                owasp=owasp,
    
                fix_time=fix_time,
    
            )
    
        )
    


    def check_hidden(
        self,
        report,
        form,
        field,
    ):
    
        sensitive = {
    
            "price",
    
            "amount",
    
            "discount",
    
            "role",
    
            "admin",
    
            "userid",
    
            "user_id",
    
            "account",
    
            "accountid",
    
            "account_id",
    
            "wallet",
    
            "balance",
    
            "coupon",
    
            "promo",
    
            "giftcard",
    
            "points",
    
            "credit",
    
            "credits",
    
            "token",
    
            "session",
    
            "isadmin",
    
            "permission",
    
            "permissions",
    
            "quantity",
    
        }
    
        name = (
            field.name or ""
        ).lower()
    
        for keyword in sensitive:
    
            if keyword in name:
    
                self.report_issue(
    
                    report,
    
                    "Medium",
    
                    "Sensitive Hidden Field Detected",
    
                    (
                        f"Hidden field '{field.name}' may contain "
                        "security-sensitive data."
                    ),
    
                    (
                        "Do not trust hidden form fields for security decisions. "
                        "Validate all values on the server."
                    ),
    
                    form,
    
                    field,
    
                    evidence=(
                        f"Hidden input name contains '{keyword}'."
                    ),
    
                    confidence="Medium",
    
                    impact=(
                        "Client-side hidden values can be modified before "
                        "submission."
                    ),
    
                    cwe="CWE-602",
    
                    owasp="A01:2021 - Broken Access Control",
    
                    fix_time="30-60 minutes",
    
                )
    
                break
    
        if field.value:
    
            self.report_issue(
    
                report,
    
                "Info",
    
                "Hidden Field Contains Default Value",
    
                (
                    f"Hidden field '{field.name}' contains a preset value."
                ),
    
                (
                    "Ensure preset values are validated on the server and "
                    "cannot be trusted solely because they originate from the client."
                ),
    
                form,
    
                field,
    
                evidence=f"Default value: {field.value}",
    
                confidence="Low",
    
                cwe="CWE-602",
    
                owasp="A01:2021 - Broken Access Control",
    
                fix_time="10 minutes",
    
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
    
        suspicious = {
    
            "token",
    
            "secret",
    
            "apikey",
    
            "api_key",
    
            "jwt",
    
            "auth",
    
            "access_token",
    
            "refresh_token",
    
            "session",
    
            "sessionid",
    
            "csrf",
    
            "csrf_token",
    
        }
    
        name = (
            field.name or ""
        ).lower()
    
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
    
        for keyword in suspicious:
    
            if keyword in name:
    
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
    
                    evidence=f"Matched keyword '{keyword}'.",
    
                    confidence="Medium",
    
                    impact=(
                        "Client-side values can be modified before submission."
                    ),
    
                    cwe="CWE-602",
    
                    owasp="A01:2021 - Broken Access Control",
    
                    fix_time="10 minutes",
    
                )
    
                break
    
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

                report.issues.append(

                            SecurityIssue(

                                severity="Low",

                                title="Number Field Has No Limits",

                                category="Input Validation",

                                description=(
                                    f"Number field '{field.name}' does not "
                                    "define any limits."
                                ),

                                recommendation=(
                                    "Validate numeric ranges on both the client "
                                    "and the server."
                                ),

                                endpoint=form.action,

                                parameter=field.name,

                            )

                        )

                # --------------------------
                # Required Fields
                # --------------------------

                if not field.required:

                    report.issues.append(

                        SecurityIssue(

                            severity="Info",

                            title="Optional Input Field",

                            category="Input Validation",

                            description=(
                                f"Field '{field.name}' is optional."
                            ),

                            recommendation=(
                                "Verify that optional fields are intentionally "
                                "optional."
                            ),

                            endpoint=form.action,

                            parameter=field.name,

                        )

                    )