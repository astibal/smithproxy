from _common import script

PPlayScript = script("udp_syslog_boundaries", [
    b"<0>emergency", b"<191>local7.debug " + b"x" * 1024,
    b"<13>ack-one", b"<13>ack-two",
], "ccss")
