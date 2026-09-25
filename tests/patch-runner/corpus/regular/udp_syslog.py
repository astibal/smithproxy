from _common import script

PPlayScript = script("udp_syslog", [
    b"<134>1 2026-09-22T01:00:00Z runner app 123 ID47 - parser smoke test",
    b"<134>1 2026-09-22T01:00:01Z collector ack 1 ACK - received",
], "cs")
