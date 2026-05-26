import argparse
import asyncio
import mimetypes
import os
import sys
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class StaticHttp3ServerProtocol(QuicConnectionProtocol):
    def __init__(self, *args, www_root, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._www_root = Path(www_root).resolve()

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                self._handle_headers(http_event.stream_id, http_event.headers)

    def _handle_headers(self, stream_id, headers):
        request_headers = {name: value for name, value in headers}
        method = request_headers.get(b":method", b"").decode("ascii", errors="replace")
        raw_path = request_headers.get(b":path", b"/").decode("utf-8", errors="replace")
        path = raw_path.split("?", 1)[0]

        if method != "GET":
            self._send_response(stream_id, 405, b"method not allowed", [(b"content-type", b"text/plain")])
            return

        status, body, response_headers = self._resolve_response(path)
        self._send_response(stream_id, status, body, response_headers, split_payload_size=17 if path == "/split-data.bin" else None)

    def _resolve_response(self, path):
        if path == "/many-headers.txt":
            headers = [(b"content-type", b"text/plain")]
            for index in range(64):
                headers.append((f"x-incursa-header-{index:02d}".encode("ascii"), b"present"))
            return 200, b"many headers\n", headers

        if path == "/split-data.bin":
            return 200, bytes(index % 251 for index in range(4096)), [(b"content-type", b"application/octet-stream")]

        relative = path.lstrip("/") or "index.html"
        candidate = (self._www_root / relative).resolve()
        if not str(candidate).startswith(str(self._www_root)) or not candidate.is_file():
            return 404, b"not found\n", [(b"content-type", b"text/plain")]

        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        return 200, candidate.read_bytes(), [(b"content-type", content_type.encode("ascii"))]

    def _send_response(self, stream_id, status, body, headers, split_payload_size=None):
        response_headers = [(b":status", str(status).encode("ascii"))]
        response_headers.extend(headers)
        response_headers.append((b"content-length", str(len(body)).encode("ascii")))
        self._http.send_headers(stream_id=stream_id, headers=response_headers)

        if split_payload_size is None or split_payload_size <= 0:
            self._http.send_data(stream_id=stream_id, data=body, end_stream=True)
        else:
            offset = 0
            while offset < len(body):
                chunk = body[offset : offset + split_payload_size]
                offset += len(chunk)
                self._http.send_data(stream_id=stream_id, data=chunk, end_stream=offset >= len(body))
            if not body:
                self._http.send_data(stream_id=stream_id, data=b"", end_stream=True)

        self.transmit()


async def main_async(args):
    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(args.cert, args.key)

    await serve(
        args.host,
        args.port,
        configuration=configuration,
        create_protocol=lambda *protocol_args, **protocol_kwargs: StaticHttp3ServerProtocol(
            *protocol_args,
            www_root=args.www_root,
            **protocol_kwargs,
        ),
    )
    print(f"aioquic HTTP/3 server serving {args.www_root} on {args.host}:{args.port}", flush=True)
    await asyncio.Event().wait()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("www_root")
    parser.add_argument("cert")
    parser.add_argument("key")
    parser.add_argument("port", type=int)
    parser.add_argument("--host", default="0.0.0.0")
    return parser.parse_args()


def main():
    try:
        asyncio.run(main_async(parse_args()))
        return 0
    except Exception as exc:
        print(repr(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
