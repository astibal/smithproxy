#!/usr/bin/env python3
"""Hold many verified TCP echo sessions open until the caller releases them."""
import argparse, concurrent.futures, pathlib, socket, time

def open_session(index, timeout):
    sock = socket.create_connection(("198.18.20.2", 9998), timeout=timeout)
    sock.settimeout(timeout)
    payload = f"session-list-load-{index:04d}\n".encode()
    sock.sendall(payload)
    reply = bytearray()
    while len(reply) < len(payload):
        chunk = sock.recv(len(payload) - len(reply))
        if not chunk: raise RuntimeError(f"session {index}: short echo")
        reply.extend(chunk)
    if reply != payload: raise RuntimeError(f"session {index}: payload mismatch")
    return sock

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--connections", type=int, default=256)
    p.add_argument("--ready", type=pathlib.Path, required=True)
    p.add_argument("--stop", type=pathlib.Path, required=True)
    p.add_argument("--timeout", type=float, default=5.0)
    a = p.parse_args(); sockets = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=96) as pool:
            futures = [pool.submit(open_session, i, a.timeout) for i in range(a.connections)]
            sockets = [future.result() for future in futures]
        a.ready.write_text(f"{len(sockets)}\n")
        deadline = time.monotonic() + 30
        while not a.stop.exists():
            if time.monotonic() >= deadline: raise TimeoutError("load was not released")
            time.sleep(0.05)
    finally:
        for sock in sockets: sock.close()

if __name__ == "__main__": main()
