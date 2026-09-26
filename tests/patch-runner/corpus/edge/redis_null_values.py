from _common import script

PPlayScript = script("redis_null_values", [
    b"*2\r\n$3\r\nGET\r\n$7\r\nmissing\r\n", b"$-1\r\n",
    b"*2\r\n$4\r\nMGET\r\n$0\r\n\r\n", b"*2\r\n$-1\r\n$0\r\n\r\n",
], "cscs")
