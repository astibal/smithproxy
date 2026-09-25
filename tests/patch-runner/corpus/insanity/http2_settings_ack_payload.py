from _common import H2_PREFACE, h2_settings, script

PPlayScript = script("http2_settings_ack_payload", [
    H2_PREFACE + h2_settings(flags=1, payload=b"not-empty"),
    h2_settings(),
], "cs")
