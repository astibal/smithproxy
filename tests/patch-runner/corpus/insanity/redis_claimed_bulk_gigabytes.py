from _common import script

PPlayScript = script("redis_claimed_bulk_gigabytes", [
    b"$999999999999999999999999\r\nsmall\r\n",
    b"-ERR invalid bulk length\r\n",
], "cs")
