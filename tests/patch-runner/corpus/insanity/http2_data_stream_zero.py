from _common import H2_PREFACE, h2_data, h2_settings, script

PPlayScript = script("http2_data_stream_zero", [
    H2_PREFACE + h2_settings() + h2_data(0, b"illegal connection data"),
    h2_settings(),
], "cs")
