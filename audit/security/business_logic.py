import copy
import json
import re
from urllib.parse import parse_qsl, urlencode

from .models import SecurityIssue
from .request_replayer import RequestReplayer
from .shared import text_snippet


class BusinessLogicTester:

    def __init__(self, aggressive=False):

        self.aggressive = aggressive
        self.replayer = RequestReplayer()

        self.max_requests = 6
        self.max_mutations = 3

        self.price_keywords = (
            "price",
            "fee",
            "amount",
            "total",
            "subtotal",
            "discount",
            "tax",
            "shipping",
            "cost",
            "charge",
            "balance",
            "rate",
            "unitprice",
            "unit_price",
        )

        self.quantity_keywords = (
            "quantity",
            "qty",
            "count",
            "units",
            "pieces",
            "items",
        )

        self.success_markers = (
            "success",
            "accepted",
            "processed",
            "updated",
            "saved",
            "completed",
            "placed",
            "charged",
            "paid",
            "confirmed",
            "ok",
        )

        self.numeric_pattern = re.compile(
            r"(?<!\w)-?\d+(?:\.\d+)?"
        )

    # ----------------------------------

    def _name_matches(
        self,
        name,
        keywords,
    ):

        lower = str(name or "").lower()

        return any(
            keyword in lower
            for keyword in keywords
        )

    def _looks_candidate(
        self,
        name,
        value,
    ):

        if self._name_matches(
            name,
            self.price_keywords,
        ):
            return True

        if self._name_matches(
            name,
            self.quantity_keywords,
        ):
            return True

        if self._name_matches(
            name,
            (
                "discount",
                "coupon",
                "promo",
                "voucher",
            ),
        ):
            return True

        return False

    def _field_family(
        self,
        name,
    ):

        lower = str(name or "").lower()

        if self._name_matches(
            lower,
            (
                "discount",
                "coupon",
                "promo",
            ),
        ):
            return "discount"

        if self._name_matches(
            lower,
            self.quantity_keywords,
        ):
            return "quantity"

        if self._name_matches(
            lower,
            self.price_keywords,
        ):
            return "monetary"

        return "numeric"

    def _replace_numeric(
        self,
        original,
        replacement,
    ):

        text = str(original or "")

        if not text:
            return replacement

        def _swap(match):
            prefix = text[: match.start()]
            suffix = text[match.end() :]

            return prefix + replacement + suffix

        if self.numeric_pattern.search(text):
            return self.numeric_pattern.sub(
                _swap,
                text,
                count=1,
            )

        return replacement

    def _mutated_value(
        self,
        name,
        value,
    ):

        family = self._field_family(
            name
        )

        if family == "quantity":
            return self._replace_numeric(
                value,
                "1",
            )

        if family == "discount":
            return self._replace_numeric(
                value,
                "100",
            )

        if family == "monetary":
            return self._replace_numeric(
                value,
                "0.01",
            )

        if self.numeric_pattern.search(
            str(value or "")
        ):
            return self._replace_numeric(
                value,
                "0.01",
            )

        return "0"

    def _parse_json_body(
        self,
        request,
    ):

        body = str(request.body or "").strip()

        if not body:
            return None

        content_type = str(request.content_type or "").lower()

        if (
            "json" not in content_type
            and not body.startswith("{")
            and not body.startswith("[")
        ):
            return None

        try:

            return json.loads(body)

        except Exception:

            return None

    def _parse_form_body(
        self,
        request,
    ):

        body = str(request.body or "").strip()

        if not body:
            return None

        content_type = str(request.content_type or "").lower()

        if "x-www-form-urlencoded" not in content_type and "=" not in body:
            return None

        pairs = parse_qsl(
            body,
            keep_blank_values=True,
        )

        if not pairs:
            return None

        form = {}

        for key, value in pairs:
            form[key] = value

        return form

    def _flatten_json(
        self,
        value,
        path=(),
    ):

        if isinstance(value, dict):

            for key, item in value.items():

                yield from self._flatten_json(
                    item,
                    path + (str(key),),
                )

        elif isinstance(value, list):

            for index, item in enumerate(value):

                yield from self._flatten_json(
                    item,
                    path + (index,),
                )

        else:

            yield path, value

    def _set_json_path(
        self,
        value,
        path,
        replacement,
    ):

        if not path:
            return replacement

        head = path[0]
        tail = path[1:]

        if isinstance(value, dict):

            clone = copy.deepcopy(value)

            if not tail:
                clone[head] = replacement
                return clone

            if head in clone:
                clone[head] = self._set_json_path(
                    clone[head],
                    tail,
                    replacement,
                )

            return clone

        if isinstance(value, list):

            clone = copy.deepcopy(value)

            if isinstance(head, int) and 0 <= head < len(clone):

                if not tail:
                    clone[head] = replacement
                else:
                    clone[head] = self._set_json_path(
                        clone[head],
                        tail,
                        replacement,
                    )

            return clone

        return value

    def _request_candidates(
        self,
        request,
    ):

        candidates = []

        for name, value in (request.params or {}).items():

            if self._looks_candidate(
                name,
                value,
            ):

                candidates.append(
                    {
                        "source": "params",
                        "name": name,
                        "value": value,
                    }
                )

        json_body = self._parse_json_body(
            request
        )

        if json_body is not None:

            for path, value in self._flatten_json(
                json_body
            ):

                if not path:
                    continue

                name = str(
                    path[-1]
                )

                if self._looks_candidate(
                    name,
                    value,
                ):

                    candidates.append(
                        {
                            "source": "json",
                            "name": name,
                            "value": value,
                            "path": path,
                            "json_body": json_body,
                        }
                    )

        form_body = self._parse_form_body(
            request
        )

        if form_body is not None:

            for name, value in form_body.items():

                if self._looks_candidate(
                    name,
                    value,
                ):

                    candidates.append(
                        {
                            "source": "form",
                            "name": name,
                            "value": value,
                            "form_body": form_body,
                        }
                    )

        return candidates

    def _apply_candidate(
        self,
        request,
        candidate,
    ):

        mutated = self.replayer.clone(
            request
        )

        replacement = self._mutated_value(
            candidate["name"],
            candidate["value"],
        )

        if candidate["source"] == "params":

            self.replayer.set_parameter(
                mutated,
                candidate["name"],
                replacement,
            )

        elif candidate["source"] == "json":

            mutated_json = self._set_json_path(
                candidate["json_body"],
                candidate["path"],
                replacement,
            )

            mutated.body = json.dumps(
                mutated_json,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            mutated.content_type = (
                mutated.content_type
                or "application/json"
            )

        elif candidate["source"] == "form":

            mutated_form = copy.deepcopy(
                candidate["form_body"]
            )
            mutated_form[
                candidate["name"]
            ] = replacement
            mutated.body = urlencode(
                mutated_form,
                doseq=True,
            )
            mutated.content_type = (
                mutated.content_type
                or "application/x-www-form-urlencoded"
            )

        return mutated, replacement

    def _looks_accepted(
        self,
        response,
        replacement,
    ):

        if not response.get(
            "success",
            False,
        ):
            return False

        status_code = int(
            response.get(
                "status_code",
                0,
            )
            or 0
        )

        if not (
            200 <= status_code < 400
        ):
            return False

        body = str(
            response.get(
                "body",
                "",
            )
        ).lower()

        if replacement and replacement.lower() in body:
            return True

        return any(
            marker in body
            for marker in self.success_markers
        )

    def _passive_findings(
        self,
        website,
        report,
    ):

        seen = set()

        for form in report.forms:

            for field in form.fields:

                name = field.name or ""

                if not self._looks_candidate(
                    name,
                    field.value,
                ):
                    continue

                key = (
                    "business-logic"
                    f"|{form.action}"
                    f"|{name.lower()}"
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                report.issues.append(

                    SecurityIssue(

                        severity="Medium",

                        title="Potential Price or Fee Manipulation Point",

                        category="Business Logic",

                        description=(
                            f"The field '{name}' looks client-controlled and may "
                            "influence pricing, fees, totals, or quantities."
                        ),

                        recommendation=(
                            "Recalculate pricing, fees, discounts, taxes, and "
                            "totals on the server, and ignore client-supplied "
                            "monetary values."
                        ),

                        endpoint=form.action,

                        parameter=name,

                        evidence=(
                            f"Client field '{name}' with value "
                            f"'{text_snippet(field.value)}'."
                        ),

                        confidence="NEEDS_MANUAL_REVIEW",

                        cwe="CWE-840",

                        owasp="A04:2021 - Insecure Design",

                        fix_time="2-6 hours",

                        verification_method="Static form review",

                        finding_key=key,

                        affected_item=name,

                    )

                )

        for request in report.requests:

            for name, value in (request.params or {}).items():

                if not self._looks_candidate(
                    name,
                    value,
                ):
                    continue

                key = (
                    "business-logic"
                    f"|{request.url}"
                    f"|{name.lower()}"
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                report.issues.append(

                    SecurityIssue(

                        severity="Medium",

                        title="Potential Price or Fee Manipulation Point",

                        category="Business Logic",

                        description=(
                            f"The request parameter '{name}' appears "
                            "client-controlled and may alter the price or "
                            "quantity used by the server."
                        ),

                        recommendation=(
                            "Recalculate server-side order totals and compare "
                            "them against authoritative pricing data."
                        ),

                        endpoint=request.url,

                        parameter=name,

                        evidence=(
                            f"Captured request parameter '{name}' with value "
                            f"'{text_snippet(value)}'."
                        ),

                        confidence="NEEDS_MANUAL_REVIEW",

                        cwe="CWE-840",

                        owasp="A04:2021 - Insecure Design",

                        fix_time="2-6 hours",

                        verification_method="Captured request review",

                        finding_key=key,

                        affected_item=name,

                    )

                )

    def _active_findings(
        self,
        report,
    ):

        for request in report.requests[: self.max_requests]:

            candidates = self._request_candidates(
                request
            )

            if not candidates:
                continue

            print(
                f"[Security][Business Logic] Replaying {request.url}",
                flush=True,
            )

            for candidate in candidates[: self.max_mutations]:

                mutated, replacement = self._apply_candidate(
                    request,
                    candidate,
                )

                print(
                    f"[Security][Business Logic] Trying {candidate['name']}",
                    flush=True,
                )

                response = self.replayer.replay(
                    mutated
                )

                if not self._looks_accepted(
                    response,
                    replacement,
                ):
                    continue

                response_body = text_snippet(
                    response.get(
                        "body",
                        "",
                    )
                )

                report.issues.append(

                    SecurityIssue(

                        severity="High",

                        title="Confirmed Price or Fee Manipulation",

                        category="Business Logic",

                        description=(
                            "A client-controlled pricing or quantity field was "
                            "tampered with and the server accepted the modified "
                            "request."
                        ),

                        recommendation=(
                            "Recalculate totals server-side, reject client-supplied "
                            "price or fee values, and validate order state against "
                            "authoritative records."
                        ),

                        endpoint=mutated.url,

                        parameter=candidate["name"],

                        payload=replacement,

                        original_value=str(
                            candidate["value"]
                        ),

                        modified_value=replacement,

                        response_code=response.get(
                            "status_code"
                        ),

                        response_time=response.get(
                            "response_time"
                        ),

                        evidence=(
                            f"Tampered request was accepted. Response snippet: "
                            f"{response_body}"
                        ),

                        verification="Confirmed",

                        notes=(
                            "Yes, it is possible. The modified request was "
                            "accepted by the server."
                        ),

                        impact=(
                            "An attacker may be able to lower prices, remove "
                            "fees, or change order quantities."
                        ),

                        confidence="VERIFIED",

                        cwe="CWE-840",

                        owasp="A04:2021 - Insecure Design",

                        fix_time="4-8 hours",

                        verification_method="Request replay verification",

                        finding_key=(
                            "business-logic-confirmed"
                            f"|{mutated.url}"
                            f"|{candidate['name'].lower()}"
                        ),

                        affected_item=candidate["name"],

                        affected_items=[
                            candidate["name"],
                        ],

                    )

                )

                return

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        self._passive_findings(
            website,
            report,
        )

        if not self.aggressive:
            return

        self._active_findings(
            report,
        )
