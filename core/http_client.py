"""
core/http_client.py
Thin wrapper around requests.Session shared by all modules: consistent
timeouts, header injection for multi-identity testing, and response timing
capture used by the baseline/anomaly layer.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.logging_utils import get_logger, redact_text

log = get_logger("http_client")


@dataclass
class TimedResponse:
    status_code: int
    headers: dict
    text: str
    elapsed_ms: float
    url: str
    request_method: str
    request_summary: str
    response_summary: str


class HttpClient:
    def __init__(self, timeout: float = 10.0, verify_tls: bool = True):
        self.timeout = timeout
        self.session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = verify_tls
        self.session.headers.update({"User-Agent": "CyFoxGuard/1.0 (authorized-pentest-scan)"})

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        params: Optional[dict] = None,
        data: Any = None,
        json_body: Any = None,
        identity_headers: Optional[dict] = None,
    ) -> TimedResponse:
        hdrs = dict(headers or {})
        if identity_headers:
            hdrs.update(identity_headers)

        start = time.monotonic()
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=hdrs,
                params=params,
                data=data,
                json=json_body,
                timeout=self.timeout,
                allow_redirects=True,
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            req_summary = redact_text(f"{method.upper()} {url} params={params} headers={list(hdrs.keys())}")
            resp_summary = redact_text(f"HTTP {resp.status_code} in {elapsed_ms:.1f}ms, {len(resp.content)} bytes")
            return TimedResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                elapsed_ms=elapsed_ms,
                url=resp.url,
                request_method=method.upper(),
                request_summary=req_summary,
                response_summary=resp_summary,
            )
        except requests.RequestException as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.warning(f"Request failed: {method} {url}: {e}")
            return TimedResponse(
                status_code=0,
                headers={},
                text="",
                elapsed_ms=elapsed_ms,
                url=url,
                request_method=method.upper(),
                request_summary=redact_text(f"{method.upper()} {url}"),
                response_summary=f"ERROR: {e.__class__.__name__}",
            )

    def get(self, url: str, **kwargs) -> TimedResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> TimedResponse:
        return self.request("POST", url, **kwargs)
