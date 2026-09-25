from _common import script

PPlayScript = script("http1_cache_validation", [
    b"GET /cached HTTP/1.1\r\nHost: origin.runner.lab\r\nIf-None-Match: \"abc123\"\r\nIf-Modified-Since: Mon, 21 Sep 2026 10:00:00 GMT\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nETag: \"abc123\"\r\nCache-Control: max-age=60\r\n\r\n",
], "cs")
