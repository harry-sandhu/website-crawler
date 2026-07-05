import copy
import time

from .models import RequestData

from urllib.parse import (
    urlparse,
    parse_qs,
)

try:
    import httpx
except ImportError:  # pragma: no cover - optional dependency in tests
    httpx = None


class RequestReplayer:

    def __init__(self):

        pass

    # ----------------------------------


    def replay(
        self,
        request: RequestData,
    ):

        start = time.perf_counter()

        if httpx is None:

            elapsed = (
                time.perf_counter() - start
            ) * 1000

            return {

                "success": False,

                "error": "httpx is not installed",

                "response_time": elapsed,

            }

        try:

            timeout = httpx.Timeout(
                connect=5.0,
                read=8.0,
                write=8.0,
                pool=5.0,
            )
    
            response = httpx.request(
    
                method=request.method,
    
                url=request.url,
    
                headers=request.headers,
    
                params=request.params,
    
                content=request.body,
    
                cookies=request.cookies,
    
                follow_redirects=True,
    
                timeout=timeout,
    
            )
    
            elapsed = (
                time.perf_counter() - start
            ) * 1000
    
            return {
    
                "success": True,
    
                "status_code": response.status_code,
    
                "headers": dict(response.headers),
    
                "body": response.text,
    
                "cookies": dict(response.cookies),
    
                "response_time": elapsed,
    
                "url": str(response.url),
    
            }
    
        except Exception as e:
    
            elapsed = (
                time.perf_counter() - start
            ) * 1000
    
            return {
    
                "success": False,
    
                "error": str(e),
    
                "response_time": elapsed,
    
            }

    def capture(
        self,
        request,
    ):
    
        parsed = urlparse(
            request.get(
                "url",
                "",
            )
        )
    
        params = {}
    
        for key, values in parse_qs(
            parsed.query
        ).items():
    
            if values:
    
                params[key] = values[0]
    
        return RequestData(
    
            method=request.get(
                "method",
                "GET",
            ),
    
            url=request.get(
                "url",
                "",
            ),
    
            headers=copy.deepcopy(
                request.get(
                    "headers",
                    {},
                )
            ),
    
            params=params,
    
            body=request.get(
                "body",
                "",
            ),
    
            cookies=copy.deepcopy(
                request.get(
                    "cookies",
                    {},
                )
            ),
    
            content_type=request.get(
                "content_type",
                "",
            ),
    
            response_status=request.get(
                "response_status",
                0,
            ),
    
            response_headers=copy.deepcopy(
                request.get(
                    "response_headers",
                    {},
                )
            ),
    
        )

    # ----------------------------------

    def clone(
        self,
        request: RequestData,
    ):

        return copy.deepcopy(
            request
        )

    # ----------------------------------

    def set_parameter(
        self,
        request: RequestData,
        key,
        value,
    ):

        request.params[key] = value

    # ----------------------------------


    def set_cookie(
        self,
        request: RequestData,
        key,
        value,
    ):
        request.cookies[key] = value
    
    
    def remove_parameter(
        self,
        request: RequestData,
        key,
    ):
        request.params.pop(key, None)
    
    
    def remove_header(
        self,
        request: RequestData,
        key,
    ):
        request.headers.pop(key, None)
    
    
    def remove_cookie(
        self,
        request: RequestData,
        key,
    ):
        request.cookies.pop(key, None)
    
    
    def clear_body(
        self,
        request: RequestData,
    ):
        request.body = ""
    
    
    

    def set_method(
        self,
        request: RequestData,
        method,
    ):
        request.method = method.upper()
    
    
    def set_url(
        self,
        request: RequestData,
        url,
    ):
        request.url = url

    def set_body(
        self,
        request: RequestData,
        body,
    ):

        request.body = body

    # ----------------------------------

    

    def set_header(
        self,
        request: RequestData,
        key,
        value,
    ):

        request.headers[key] = value
