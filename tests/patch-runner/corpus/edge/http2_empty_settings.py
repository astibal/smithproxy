from _common import H2_PREFACE, h2_settings, script

PPlayScript = script("http2_empty_settings", [
    H2_PREFACE + h2_settings() + h2_settings(flags=1),
    h2_settings() + h2_settings(flags=1),
], "cs")
