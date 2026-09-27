from _common import script

PPlayScript = script("redis_resp", [
    b"*2\r\n$3\r\nGET\r\n$7\r\ncounter\r\n",
    b"$2\r\n42\r\n",
    b"*3\r\n$3\r\nSET\r\n$7\r\ncounter\r\n$2\r\n43\r\n",
    b"+OK\r\n",
], "cscs")
