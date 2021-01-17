from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

DEFAULT_TIMEOUT = 2


class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


def retry_http_adapter():
    retries = Retry(
        backoff_factor=1,
        status_forcelist=[400, 401, 403, 408, 429, 500, 502, 503, 504, 599],
        method_whitelist=["GET"]
    )
    # use for retries
    # return HTTPAdapter(max_retries=retries)

    # use for retries and timeout
    return retries
