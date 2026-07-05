from .models import (
    FormData,
    FormField,
)


class FormFuzzer:

    def __init__(self):

        self.payloads = {

            "text": [

                "",
                "a",
                "A" * 256,
                "<script>alert(1)</script>",
                "' OR 1=1 --",
                "../../../etc/passwd",
                "null",
                "undefined",

            ],

            "email": [

                "",
                "a",
                "abc",
                "@",
                "test",
                "test@",
                "test@test",
                "test@test.",
                "test@example.com",

            ],

            "number": [

                "-1",
                "0",
                "1",
                "999999999",
                "999999999999999999",
                "1.5",
                "NaN",
                "Infinity",

            ],

            "phone": [

                "",
                "1",
                "123",
                "abcdefgh",
                "+1234567890",
                "99999999999999999999",

            ],

            "password": [

                "",
                "123",
                "password",
                "Password123",
                "P@ssw0rd!",
                "A" * 256,

            ],

        }

    # ----------------------------------

    def discover(
        self,
        page,
    ):

        forms = []

        js_forms = page.evaluate(
            """
            () => {
                    
                    return Array.from(
                            document.forms
                        ).map(form => ({
                    
                            id: form.id,
                    
                            name: form.name,
                    
                            action: form.action,
                    
                            method: form.method || "GET",
                    
                            enctype: form.enctype,

                            autocomplete: form.autocomplete || "",

                            target: form.target || "",

                            novalidate: form.noValidate || false,

                            pageUrl: location.href,
                    
                            fields: Array.from(
                                form.elements
                            ).map(field => ({
                    
                                name: field.name,
                    
                                type: field.type || "text",
                    
                                required: field.required,
                    
                                value: field.value,
                    
                                placeholder: field.placeholder,
                    
                                pattern: field.pattern,
                    
                                autocomplete: field.autocomplete,
                    
                                minlength: field.minLength,
                    
                                maxlength: field.maxLength,
                    
                                min: field.min,
                    
                                max: field.max,
                    
                                step: field.step,
                    
                                readonly: field.readOnly,
                    
                                disabled: field.disabled,
                    
                                multiple: field.multiple,

                                accept: field.accept,
                    
                            })),
                    
                        }));
                    
                    }
            """
        )

        for form in js_forms:

            fields = []

            for field in form["fields"]:

                fields.append(

                    FormField(
                            
                                name=field["name"],
                            
                                field_type=field["type"],
                            
                                required=field["required"],
                            
                                value=field["value"],
                            
                                placeholder=field["placeholder"],
                            
                                pattern=field["pattern"],
                            
                                autocomplete=field["autocomplete"],
                            
                                minlength=field["minlength"],
                            
                                maxlength=field["maxlength"],
                            
                                min=field["min"],
                            
                                max=field["max"],
                            
                                step=field["step"],
                            
                                readonly=field["readonly"],
                            
                                disabled=field["disabled"],
                            
                                multiple=field["multiple"],

                                accept=field["accept"],
                            
                            )

                )

            forms.append(

                FormData(

                    id=form["id"],

                    name=form["name"],

                    action=form["action"],

                    method=form["method"],

                    url=form["pageUrl"],

                    enctype=form["enctype"],

                    autocomplete=form["autocomplete"],

                    target=form["target"],

                    novalidate=form["novalidate"],

                    fields=fields,

                )

            )

        return forms

    # ----------------------------------

    def payloads_for(
        self,
        field: FormField,
    ):

        field_type = field.field_type.lower()

        if field_type == "email":

            return self.payloads["email"]

        if field_type == "number":

            return self.payloads["number"]

        if field_type == "tel":

            return self.payloads["phone"]

        if field_type == "password":

            return self.payloads["password"]

        return self.payloads["text"]

    # ----------------------------------

    def run(
        self,
        website,
        report,
    ):

        forms = self.discover(
            website.page_object
        )

        report.forms.extend(
            forms
        )
