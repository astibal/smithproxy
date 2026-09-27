from _common import H2_PREFACE, h2_data, h2_headers, h2_settings, script

# Static/literal HPACK subset: POST, http, authority, path and content-type.
request_headers = b"\x83\x86\x01\x11origin.runner.lab\x04\x0c/demo.Method\x0f\x10\x10application/grpc"
response_headers = b"\x88\x0f\x10\x10application/grpc"
grpc_request = b"\x00\x00\x00\x00\x05hello"
grpc_response = b"\x00\x00\x00\x00\x05world"
PPlayScript = script("http2_grpc_like", [
    H2_PREFACE + h2_settings() + h2_headers(1, request_headers, flags=0x04) + h2_data(1, grpc_request),
    h2_settings() + h2_headers(1, response_headers, flags=0x04) + h2_data(1, grpc_response),
], "cs")
