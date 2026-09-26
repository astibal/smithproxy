from _common import script

PPlayScript = script("udp_tftp", [
    b"\x00\x01readme.txt\x00octet\x00",
    b"\x00\x03\x00\x01hello from tftp\n",
    b"\x00\x04\x00\x01",
], "csc")
