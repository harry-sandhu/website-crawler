from .models import SecurityIssue


class BusinessLogicTester:

    def __init__(self):

        self.interesting_fields = {

            "price",
            "cost",
            "amount",
            "total",
            "subtotal",
            "discount",
            "coupon",
            "promo",
            "voucher",
            "giftcard",
            "gift_card",
            "shipping",
            "delivery",
            "tax",
            "fee",
            "quantity",
            "qty",
            "stock",
            "inventory",
            "balance",
            "wallet",
            "credit",
            "credits",
            "points",
            "reward",
            "currency",
            "rate",
            "plan",
            "subscription",

        }

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        for form in report.forms:

            for field in form.fields:

                name = (
                    field.name or ""
                ).lower()

                if not name:
                    continue

                for keyword in self.interesting_fields:

                    if keyword in name:

                        report.issues.append(

                            SecurityIssue(

                                severity="Medium",

                                title="Potential Business Logic Target",

                                category="Business Logic",

                                description=(
                                    f"Input field '{field.name}' may "
                                    "influence pricing, payments, inventory, "
                                    "or other sensitive business logic."
                                ),

                                recommendation=(
                                    "Verify on the server that client-supplied "
                                    "values cannot manipulate business rules."
                                ),

                                endpoint=form.action,

                                parameter=field.name,

                                evidence=f"Field name matched '{keyword}'.",

                                impact=(
                                    "If trusted by the backend, attackers "
                                    "could manipulate prices, discounts, "
                                    "quantities, credits, or similar values."
                                ),

                                confidence="Medium",

                                cwe="CWE-840",

                                owasp="A01 Broken Access Control",

                                fix_time="2-4 hours",

                            )

                        )

                        break

        # ----------------------------------
        # Hidden Inputs
        # ----------------------------------

        for form in report.forms:

            for field in form.fields:

                if field.field_type.lower() == "hidden":

                    report.issues.append(

                        SecurityIssue(

                            severity="Low",

                            title="Hidden Form Field",

                            category="Business Logic",

                            description=(
                                f"Hidden input '{field.name}' "
                                "was found."
                            ),

                            recommendation=(
                                "Do not trust hidden form fields. "
                                "Validate all values server-side."
                            ),

                            endpoint=form.action,

                            parameter=field.name,

                            evidence="Hidden HTML input detected.",

                            impact=(
                                "Attackers can modify hidden inputs "
                                "using browser developer tools or "
                                "intercepting proxies."
                            ),

                            confidence="High",

                            cwe="CWE-602",

                            owasp="A01 Broken Access Control",

                            fix_time="30 minutes",

                        )

                    )