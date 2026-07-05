from .models import SecurityIssue


class IDORTester:

    def __init__(self):

        self.id_keywords = {

            "id",
            "user",
            "userid",
            "user_id",
            "account",
            "accountid",
            "account_id",
            "customer",
            "customerid",
            "customer_id",
            "member",
            "memberid",
            "member_id",
            "profile",
            "profileid",
            "profile_id",
            "order",
            "orderid",
            "order_id",
            "invoice",
            "invoiceid",
            "invoice_id",
            "payment",
            "paymentid",
            "payment_id",
            "product",
            "productid",
            "product_id",
            "document",
            "documentid",
            "document_id",
            "file",
            "filename",
            "image",
            "uuid",
            "guid",

        }

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        # ----------------------------------
        # Forms
        # ----------------------------------

        for form in report.forms:

            for field in form.fields:

                name = (
                    field.name or ""
                ).lower()

                if not name:
                    continue

                for keyword in self.id_keywords:

                    if keyword == name or keyword in name:

                        report.issues.append(

                            SecurityIssue(

                                severity="Medium",

                                title="Potential IDOR Parameter",

                                category="IDOR",

                                description=(
                                    f"Input field '{field.name}' appears "
                                    "to reference an object identifier."
                                ),

                                recommendation=(
                                    "Never rely on client-supplied identifiers. "
                                    "Always verify authorization on the server."
                                ),

                                endpoint=form.action,

                                parameter=field.name,

                                evidence=f"Matched keyword '{keyword}'.",

                                impact=(
                                    "If authorization checks are missing, "
                                    "attackers may access other users' resources."
                                ),

                                confidence="NEEDS_MANUAL_REVIEW",

                                cwe="CWE-639",

                                owasp="A01 Broken Access Control",

                                fix_time="2-6 hours",

                                verification_method="Form field inspection",

                            )

                        )

                        break

        # ----------------------------------
        # URLs
        # ----------------------------------

        links = website.page.get(
            "links",
            []
        )

        for link in links:

            url = str(link).lower()

            for keyword in self.id_keywords:

                if (
                    f"{keyword}="
                    in url
                ):

                    report.issues.append(

                        SecurityIssue(

                            severity="Low",

                            title="Potential IDOR URL Parameter",

                            category="IDOR",

                            description=(
                                "URL contains a parameter that may "
                                "identify an object."
                            ),

                            recommendation=(
                                "Verify authorization for every object "
                                "referenced by URL parameters."
                            ),

                            endpoint=url,

                            parameter=keyword,

                            evidence=url,

                            impact=(
                                "Changing object identifiers may expose "
                                "other users' data."
                            ),

                            confidence="NEEDS_MANUAL_REVIEW",

                            cwe="CWE-639",

                            owasp="A01 Broken Access Control",

                            fix_time="2-6 hours",

                            verification_method="URL parameter inspection",

                        )

                    )

                    break
