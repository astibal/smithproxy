import os
import pathlib
import time

from _common import H2_PREFACE, h2_data, h2_frame, h2_headers, h2_settings, hpack_request, hpack_response, script


packets = []
roles = []
for number, stream_id in enumerate(range(1, 24, 2), 1):
    request = h2_headers(stream_id, hpack_request(f"/command-{number:02d}".encode()))
    if number == 1:
        request = H2_PREFACE + h2_settings() + request
    packets.append(request)
    roles.append("c")

    response = h2_headers(stream_id, hpack_response()) + h2_data(
        stream_id, f"response-{number:02d}".encode()
    )
    if number == 1:
        response = h2_settings() + response
    packets.append(response)
    roles.append("s")

# Keep the completed 12-command session open while the CLI reads its history.
packets.extend([
    h2_frame(6, 0, 0, b"observe!"),
    h2_frame(6, 1, 0, b"observe!"),
])
roles.extend(["c", "s"])


BaseScript = script("http2_many_commands", packets, roles)


class PPlayScript(BaseScript):
    """Keep the multiplexed connection alive long enough for live CLI inspection."""

    def before_send(self, role, index, data):
        if role == "server" and index == len(self.origins[role]) - 1:
            ready_file = os.environ.get("HTTP2_READY_FILE")
            if ready_file:
                pathlib.Path(ready_file).write_text("ready\n")
            time.sleep(float(os.environ.get("HTTP2_OBSERVE_DELAY", "3")))
        if index:
            time.sleep(0.25)
