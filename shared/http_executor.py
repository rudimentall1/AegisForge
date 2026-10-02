import ipaddress
import os
from urllib.parse import urlparse
import requests

class HttpExecutorError(ValueError):
    pass

class HttpApiExecutor:
    MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    def __init__(self, allowed_hosts=None, timeout=10, session=None):
        self.allowed_hosts = {str(v).strip().lower() for v in (allowed_hosts or self._env_hosts()) if str(v).strip()}
        self.timeout = float(timeout)
        self.session = session or requests.Session()
    @staticmethod
    def _env_hosts():
        return [v for v in os.environ.get("AEGISFORGE_HTTP_ALLOWED_HOSTS", "").split(",") if v.strip()]
    def _validate_url(self, url):
        parsed = urlparse(str(url))
        if parsed.scheme != "http" or not parsed.hostname:
            raise HttpExecutorError("http_url_required")
        host = parsed.hostname.lower()
        if host not in self.allowed_hosts:
            raise HttpExecutorError("http_host_not_allowed")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address and not (address.is_loopback or address.is_private):
            raise HttpExecutorError("http_public_ip_blocked")
    def execute(self, intent):
        params = dict(getattr(intent, "parameters", {}) or {})
        method = str(params.get("method", "")).upper()
        if method not in self.MUTATING_METHODS:
            raise HttpExecutorError("http_mutating_method_required")
        url = params.get("url") or intent.target
        self._validate_url(url)
        headers = params.get("headers") or {}
        if {str(k).lower() for k in headers} & {"authorization", "proxy-authorization", "cookie"}:
            raise HttpExecutorError("http_sensitive_headers_forbidden")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in headers.items()):
            raise HttpExecutorError("http_headers_invalid")
        response = self.session.request(method, url, json=params.get("body"), headers=headers, timeout=self.timeout)
        try: body = response.json()
        except ValueError: body = response.text[:4096]
        if not 200 <= response.status_code < 300:
            raise HttpExecutorError(f"http_status:{response.status_code}")
        return {"method": method, "url": url, "status_code": response.status_code, "body": body}
