from playwright.sync_api import sync_playwright


class BrowserManager:
    def __init__(self, headless=True):
        self.headless = headless

        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

        # Collected Data
        self.console_messages = []
        self.js_errors = []
        self.network_requests = []
        self.failed_requests = []
        self.responses = []

    def start(self):
        self.playwright = sync_playwright().start()

        self.browser = self.playwright.chromium.launch(
            headless=self.headless
        )

        self.context = self.browser.new_context(
            viewport={
                "width": 1440,
                "height": 900
            }
        )

        self.page = self.context.new_page()

        # Register event listeners
        self.page.on("console", self._handle_console)
        self.page.on("pageerror", self._handle_page_error)
        self.page.on("request", self._handle_request)
        self.page.on("requestfailed", self._handle_failed_request)
        self.page.on("response", self._handle_response)

        return self.page

    def _handle_console(self, msg):
        self.console_messages.append(
            {
                "type": msg.type,
                "text": msg.text,
                "location": msg.location,
            }
        )

    def _handle_page_error(self, err):
        self.js_errors.append(str(err))

    def _handle_request(self, request):
        self.network_requests.append({
            "method": request.method,
            "url": request.url,
            "resource": request.resource_type
        })

    def _handle_failed_request(self, request):
        self.failed_requests.append({
            "url": request.url,
            "method": request.method,
            "resource": request.resource_type,
            "failure": request.failure
        })

    def _handle_response(self, response):
        try:
            self.responses.append({
                "url": response.url,
                "status": response.status,
                "headers": response.headers,
                "content_type": response.headers.get("content-type", "")
            })
        except Exception:
            pass

    def get_data(self):
        return {
            "console": self.console_messages,
            "js_errors": self.js_errors,
            "requests": self.network_requests,
            "failed_requests": self.failed_requests,
            "responses": self.responses,
        }

    def close(self):
        if self.browser:
            self.browser.close()

        if self.playwright:
            self.playwright.stop()