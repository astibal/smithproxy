from _common import script

PPlayScript = script("memcached_text", [
    b"set greeting 0 60 5\r\nhello\r\n", b"STORED\r\n",
    b"get greeting\r\n", b"VALUE greeting 0 5\r\nhello\r\nEND\r\n",
], "cscs")
