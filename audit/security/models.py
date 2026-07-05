from dataclasses import dataclass, field


# ----------------------------------
# Captured HTTP Request
# ----------------------------------

@dataclass
class RequestData:

    method: str

    url: str

    headers: dict

    params: dict = field(
        default_factory=dict
    )

    body: str = ""

    cookies: dict = field(
        default_factory=dict
    )

    content_type: str = ""

    response_status: int = 0

    response_headers: dict = field(
        default_factory=dict
    )


# ----------------------------------
# HTML Form
# ----------------------------------

@dataclass
class FormField:

    name: str

    field_type: str

    required: bool = False

    value: str = ""

    placeholder: str = ""

    pattern: str = ""

    autocomplete: str = ""

    minlength: int | None = None

    maxlength: int | None = None

    min: str = ""

    max: str = ""

    step: str = ""

    readonly: bool = False

    disabled: bool = False

    multiple: bool = False

    accept: str = ""


@dataclass
class FormData:

    action: str

    method: str

    id: str = ""

    name: str = ""

    url: str = ""

    enctype: str = ""

    autocomplete: str = ""

    target: str = ""

    novalidate: bool = False

    fields: list[FormField] = field(
        default_factory=list
    )


# ----------------------------------
# Security Finding
# ----------------------------------




@dataclass
class SecurityIssue:

    severity: str

    title: str

    category: str

    description: str

    recommendation: str

    endpoint: str = ""

    page: str = ""

    selector: str = ""

    parameter: str = ""

    payload: str = ""

    original_value: str = ""

    modified_value: str = ""

    response_code: int | None = None

    response_time: float | None = None

    evidence: str = ""

    notes: str = ""

    impact: str = ""

    confidence: str = ""

    cwe: str = ""

    owasp: str = ""

    fix_time: str = ""

    screenshot: str = ""


    
# ----------------------------------
# Security Report
# ----------------------------------

@dataclass
class SecurityReport:

    issues: list[SecurityIssue] = field(
        default_factory=list
    )

    requests: list[RequestData] = field(
        default_factory=list
    )

    forms: list[FormData] = field(
        default_factory=list
    )
