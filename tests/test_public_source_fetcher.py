from shared import public_source


class FakeResponse:
    status_code = 200
    headers = {"Content-Length": "20050"}
    encoding = "utf-8"

    def __init__(self, body):
        self.body = body
        self.closed = False

    def iter_content(self, chunk_size):
        for offset in range(0, len(self.body), chunk_size):
            yield self.body[offset:offset + chunk_size]

    def close(self):
        self.closed = True


def test_fetch_public_source_reports_text_truncation(monkeypatch):
    body = ("<html><body><p>" + ("A" * 20000) + "</p></body></html>").encode()
    response = FakeResponse(body)
    monkeypatch.setattr(public_source.requests, "get", lambda *args, **kwargs: response)

    result = public_source.fetch_public_source("https://ethereum.org/research")

    assert result["content_bytes"] == len(body)
    assert len(result["text"]) == public_source.MAX_TEXT_CHARS
    assert result["content_truncated_for_analysis"] is True
    assert response.closed is True


def test_fetch_public_source_reports_no_text_truncation(monkeypatch):
    body = b"<html><body><p>short source</p></body></html>"
    response = FakeResponse(body)
    monkeypatch.setattr(public_source.requests, "get", lambda *args, **kwargs: response)

    result = public_source.fetch_public_source("https://ethereum.org/research")

    assert result["text"] == "short source"
    assert result["content_truncated_for_analysis"] is False
