from _common import H2_PREFACE, h2_settings, script

PPlayScript = script("http2_fragmented_preface", [
    H2_PREFACE[:1], H2_PREFACE[1:7], H2_PREFACE[7:23], H2_PREFACE[23:] + h2_settings(),
    h2_settings(),
], "ccccs")
