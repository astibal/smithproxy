from _common import script

PPlayScript = script("http09", [b"GET /legacy\r\n", b"legacy body without response headers\n"], "cs")
