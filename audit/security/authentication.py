from .models import SecurityIssue


class AuthenticationTester:

    LOGIN_HINTS = {
        "login",
        "sign in",
        "signin",
        "log in",
        "auth",
        "authenticate",
        "session",
    }

    REGISTER_HINTS = {
        "register",
        "sign up",
        "signup",
        "create account",
        "join",
        "new account",
    }

    FORGOT_HINTS = {
        "forgot",
        "reset password",
        "recover password",
        "forgot password",
    }

    CHANGE_HINTS = {
        "change password",
        "update password",
        "set password",
    }

    RESET_HINTS = {
        "reset",
        "password reset",
        "reset token",
    }

    MFA_HINTS = {
        "mfa",
        "2fa",
        "otp",
        "one-time code",
        "verification code",
        "authenticator",
        "passcode",
        "security code",
    }

    OAUTH_HINTS = {
        "oauth",
        "openid",
        "sso",
        "single sign-on",
        "single sign on",
        "saml",
        "google",
        "microsoft",
        "apple",
        "github",
        "okta",
        "auth0",
    }

    PASSWORD_NAME_HINTS = {
        "password",
        "newpassword",
        "new_password",
        "confirm_password",
        "confirm password",
        "current_password",
        "current password",
    }

    USERNAME_HINTS = {
        "username",
        "user name",
        "email",
        "e-mail",
        "login",
        "account",
    }

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

    def _form_text(
        self,
        form,
    ):

        parts = [
            form.id,
            form.name,
            form.action,
            form.method,
            form.url,
            form.enctype,
            form.autocomplete,
            form.target,
        ]

        for field in form.fields:

            parts.extend(
                [
                    field.name,
                    field.field_type,
                    field.value,
                    field.placeholder,
                    field.pattern,
                    field.autocomplete,
                ]
            )

        return " ".join(
            str(part or "")
            for part in parts
        ).lower()

    def _page_text(
        self,
        website,
    ):

        page = website.page or {}

        parts = [
            page.get("title", ""),
            page.get("html", ""),
        ]

        for button in page.get("buttons", []):

            parts.append(
                button
            )

        for link in page.get("links", []):

            if isinstance(link, dict):

                parts.append(
                    link.get("text", "")
                )

                parts.append(
                    link.get("href", "")
                )

            else:

                parts.append(
                    str(link)
                )

        return " ".join(
            str(part or "")
            for part in parts
        ).lower()

    def _has_hint(
        self,
        text,
        hints,
    ):

        return any(
            hint in text
            for hint in hints
        )

    def _password_fields(
        self,
        form,
    ):

        return [
            field
            for field in form.fields
            if (
                (field.field_type or "").lower() == "password"
            )
        ]

    def _username_fields(
        self,
        form,
    ):

        fields = []

        for field in form.fields:

            text = " ".join(
                [
                    field.name,
                    field.field_type,
                    field.placeholder,
                    field.autocomplete,
                ]
            ).lower()

            if self._has_hint(
                text,
                self.USERNAME_HINTS,
            ):

                fields.append(
                    field
                )

        return fields

    def _record_form_issue(
        self,
        report,
        website,
        form,
        field,
        severity,
        title,
        description,
        recommendation,
        evidence,
        confidence="High",
        impact="",
        cwe="CWE-200",
        owasp="A05:2021 - Security Misconfiguration",
        fix_time="10 minutes",
    ):

        self._add_issue(
            report,
            severity=severity,
            title=title,
            category="Authentication",
            description=description,
            recommendation=recommendation,
            endpoint=form.action,
            page=website.url,
            parameter=(field.name if field else ""),
            evidence=evidence,
            confidence=confidence,
            impact=impact,
            cwe=cwe,
            owasp=owasp,
            fix_time=fix_time,
        )

    def _detect_login(
        self,
        report,
        website,
        form,
        text,
    ):

        passwords = self._password_fields(
            form,
        )

        if not passwords:
            return False

        usernames = self._username_fields(
            form,
        )

        if usernames or self._has_hint(
            text,
            self.LOGIN_HINTS,
        ):

            self._record_form_issue(
                report,
                website,
                form,
                passwords[0],
                "Info",
                "Login Form Detected",
                "A form appears to support user authentication.",
                "Review login handling, brute-force protection, MFA, and "
                "session management on the server.",
                "Password field and login-related hints were observed.",
                confidence="High",
                impact=(
                    "Login forms are sensitive attack surfaces for credential "
                    "stuffing and account enumeration."
                ),
                cwe="CWE-200",
                owasp="A07:2021 - Identification and Authentication Failures",
                fix_time="5 minutes",
            )

            return True

        return False

    def _detect_registration(
        self,
        report,
        website,
        form,
        text,
    ):

        passwords = self._password_fields(
            form,
        )

        if len(passwords) < 1:
            return False

        if self._has_hint(
            text,
            self.REGISTER_HINTS,
        ) or len(passwords) > 1:

            self._record_form_issue(
                report,
                website,
                form,
                passwords[0],
                "Info",
                "Registration Form Detected",
                "A form appears to support account creation.",
                "Validate registration flows, enforce strong passwords, "
                "and protect account creation endpoints.",
                "Registration keywords and password fields were observed.",
                confidence="High",
                impact=(
                    "Registration forms can be abused for fake account "
                    "creation and weak-password enrollment."
                ),
                cwe="CWE-200",
                owasp="A07:2021 - Identification and Authentication Failures",
                fix_time="5 minutes",
            )

            return True

        return False

    def _detect_password_reset(
        self,
        report,
        website,
        form,
        text,
    ):

        if not self._has_hint(
            text,
            self.FORGOT_HINTS | self.RESET_HINTS | self.CHANGE_HINTS,
        ):

            return False

        field = form.fields[0] if form.fields else None

        self._record_form_issue(
            report,
            website,
            form,
            field,
            "Info",
            "Password Recovery Flow Detected",
            "A form appears to support password recovery or reset.",
            "Ensure password reset tokens are short-lived, single-use, "
            "and tied to the intended account.",
            "Password recovery keywords were observed in form metadata.",
            confidence="High",
            impact=(
                "Password recovery flows are high-value targets for "
                "account takeover attacks."
            ),
            cwe="CWE-640",
            owasp="A07:2021 - Identification and Authentication Failures",
            fix_time="5 minutes",
        )

        return True

    def _detect_mfa(
        self,
        report,
        website,
        form,
        text,
    ):

        if not self._has_hint(
            text,
            self.MFA_HINTS,
        ):

            return False

        field = form.fields[0] if form.fields else None

        self._record_form_issue(
            report,
            website,
            form,
            field,
            "Info",
            "Multi-Factor Authentication Indicator Detected",
            "A form or page appears to include MFA-related controls.",
            "Ensure MFA is enforced server-side and recovery factors are "
            "handled securely.",
            "MFA-related keywords were observed.",
            confidence="Medium",
            impact=(
                "MFA indicators help identify authentication hardening "
                "and recovery flows."
            ),
            cwe="CWE-200",
            owasp="A07:2021 - Identification and Authentication Failures",
            fix_time="5 minutes",
        )

        return True

    def _detect_oauth(
        self,
        report,
        website,
        form,
        text,
    ):

        if not self._has_hint(
            text,
            self.OAUTH_HINTS,
        ):

            return False

        field = form.fields[0] if form.fields else None

        self._record_form_issue(
            report,
            website,
            form,
            field,
            "Info",
            "OAuth or SSO Integration Detected",
            "A form or page appears to offer federated login options.",
            "Review OAuth, OIDC, SAML, and SSO flows for secure callback "
            "validation and account linking behavior.",
            "OAuth or SSO keywords were observed.",
            confidence="High",
            impact=(
                "Federated login integrations can expose account-linking and "
                "redirect vulnerabilities if misconfigured."
            ),
            cwe="CWE-601",
            owasp="A07:2021 - Identification and Authentication Failures",
            fix_time="5 minutes",
        )

        return True

    def _detect_password_manager_blocking(
        self,
        report,
        website,
        form,
    ):

        password_fields = self._password_fields(
            form,
        )

        if not password_fields:
            return

        if (
            form.autocomplete or ""
        ).strip().lower() == "off":

            field = password_fields[0]

            self._record_form_issue(
                report,
                website,
                form,
                field,
                "Low",
                "Password Managers May Be Disabled",
                "The form disables autocomplete at the form level.",
                "Avoid disabling autocomplete for authentication forms so "
                "password managers can help users and reduce phishing risk.",
                "Form autocomplete='off' was observed.",
                confidence="High",
                impact=(
                    "Disabling password manager support can reduce user "
                    "security and convenience."
                ),
                cwe="CWE-200",
                owasp="A05:2021 - Security Misconfiguration",
                fix_time="5 minutes",
            )

        for field in password_fields:

            if (
                field.autocomplete or ""
            ).strip().lower() == "off":

                self._record_form_issue(
                    report,
                    website,
                    form,
                    field,
                    "Low",
                    "Password Field Autocomplete Disabled",
                    "A password field disables browser autofill support.",
                    "Use current-password or new-password where appropriate "
                    "instead of disabling autocomplete.",
                    "Password input autocomplete='off' was observed.",
                    confidence="High",
                    impact=(
                        "Password managers may not offer safe autofill "
                        "behavior when autocomplete is disabled."
                    ),
                    cwe="CWE-200",
                    owasp="A05:2021 - Security Misconfiguration",
                    fix_time="5 minutes",
                )

    def _detect_weak_password_policy(
        self,
        report,
        website,
        form,
        text,
    ):

        if not (
            self._has_hint(text, self.REGISTER_HINTS)
            or self._has_hint(text, self.CHANGE_HINTS)
        ):

            return

        for field in self._password_fields(form):

            if field.minlength is None or field.minlength < 8:

                self._record_form_issue(
                    report,
                    website,
                    form,
                    field,
                    "Medium",
                    "Weak Password Policy Inferred",
                    "A password field suggests a password policy weaker than "
                    "recommended defaults.",
                    "Require a minimum length of at least 12 characters "
                    "for new or changed passwords and add server-side checks.",
                    (
                        "Password field metadata suggests a short or missing "
                        "minimum length."
                    ),
                    confidence="Medium",
                    impact=(
                        "Weak password policy can lead to accounts protected by "
                        "low-entropy passwords."
                    ),
                    cwe="CWE-521",
                    owasp="A07:2021 - Identification and Authentication Failures",
                    fix_time="10 minutes",
                )

                return

    def run(
        self,
        website,
        report,
    ):

        page_text = self._page_text(
            website,
        )

        for form in report.forms:

            form_text = self._form_text(
                form,
            )

            combined_text = " ".join(
                [
                    form_text,
                    page_text,
                ]
            )

            self._detect_login(
                report,
                website,
                form,
                combined_text,
            )

            self._detect_registration(
                report,
                website,
                form,
                combined_text,
            )

            self._detect_password_reset(
                report,
                website,
                form,
                combined_text,
            )

            self._detect_mfa(
                report,
                website,
                form,
                combined_text,
            )

            self._detect_oauth(
                report,
                website,
                form,
                combined_text,
            )

            self._detect_password_manager_blocking(
                report,
                website,
                form,
            )

            self._detect_weak_password_policy(
                report,
                website,
                form,
                combined_text,
            )

