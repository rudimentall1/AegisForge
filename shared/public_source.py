"""Bounded public-source fetcher for reproducible security research."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

ALLOWED_SOURCE_HOSTS = {
    "blog.ethereum.org", "ethereum.org", "1inch.com", "www.1inch.com",
    "github.com", "www.github.com", "api.github.com", "raw.githubusercontent.com",
}
MAX_BODY_BYTES = 1_500_000
MAX_TEXT_CHARS = 18_000
REDIRECT_CODES = {301, 302, 303, 307, 308}


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.title_parts = [], []
        self.in_title = False
        self.hidden_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg", "template"}:
            self.hidden_depth += 1
            return
        if tag == "title":
            self.in_title = True
        if tag in {"p", "div", "article", "section", "li", "h1", "h2", "h3", "h4", "br", "tr", "blockquote"}:
            self.parts.append(" ")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg", "template"}:
            self.hidden_depth = max(0, self.hidden_depth - 1)
            return
        if tag == "title":
            self.in_title = False
        if tag in {"p", "div", "article", "section", "li", "br", "tr", "blockquote"}:
            self.parts.append(" ")

    def handle_data(self, data):
        if self.hidden_depth:
            return
        value = data.strip()
        if value:
            self.parts.append(value)
            if self.in_title:
                self.title_parts.append(value)


def _allowed_https_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url))
    except Exception:
        return False
    return parsed.scheme == "https" and parsed.hostname in ALLOWED_SOURCE_HOSTS and not parsed.username and not parsed.password


def fetch_public_source(url: str, timeout: int = 12) -> dict:
    """Fetch allowlisted HTTPS pages with a hard response-body memory bound."""
    requested_url = str(url or "").strip()
    if not _allowed_https_url(requested_url):
        raise ValueError("source_url_not_allowlisted_https")

    current_url = requested_url
    response = None
    for _ in range(4):
        if not _allowed_https_url(current_url):
            raise ValueError("redirect_target_not_allowlisted_https")
        response = requests.get(
            current_url, timeout=timeout, allow_redirects=False, stream=True,
            headers={"User-Agent": "AegisForge-Research/1.0"},
        )
        if response.status_code not in REDIRECT_CODES:
            break
        location = response.headers.get("Location")
        if not location:
            break
        next_url = urljoin(current_url, location)
        if not _allowed_https_url(next_url):
            response.close()
            raise ValueError("redirect_target_not_allowlisted_https")
        response.close()
        current_url = next_url
    else:
        raise RuntimeError("too_many_public_source_redirects")
    if response is None:
        raise RuntimeError("source_fetch_no_response")

    try:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_BODY_BYTES:
                    raise ValueError("source_body_exceeds_limit")
            except ValueError as exc:
                if str(exc) == "source_body_exceeds_limit":
                    raise
                # Ignore malformed Content-Length; the streaming limit remains authoritative.

        chunks = []
        body_size = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            if body_size + len(chunk) > MAX_BODY_BYTES:
                raise ValueError("source_body_exceeds_limit")
            chunks.append(chunk)
            body_size += len(chunk)
        body = b"".join(chunks)
        response_encoding = response.encoding or "utf-8"
        status_code = int(response.status_code)
    finally:
        response.close()

    digest = hashlib.sha256(body).hexdigest()
    try:
        html = body.decode(response_encoding, errors="replace")
    except LookupError:
        html = body.decode("utf-8", errors="replace")

    parser = _VisibleTextParser()
    if status_code == 200:
        parser.feed(html)
    visible_text = re.sub(r"\\s+", " ", " ".join(parser.parts)).strip()[:MAX_TEXT_CHARS]
    title = re.sub(r"\\s+", " ", " ".join(parser.title_parts)).strip()[:300]
    return {
        "source_url": requested_url,
        "final_url": current_url,
        "status_code": status_code,
        "fetch_status": "fetched" if status_code == 200 else f"http_{status_code}",
        "title": title or None,
        "text": visible_text,
        "excerpt": visible_text[:2200],
        "content_sha256": digest,
        "content_bytes": len(body),
        "content_truncated_for_analysis": False,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
