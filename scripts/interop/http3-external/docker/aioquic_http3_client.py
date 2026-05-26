import argparse
import asyncio
import ssl
import sys
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration


class Http3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses = {}
        self._settings_received = asyncio.get_running_loop().create_future()

    async def get(self, url):
        await asyncio.wait_for(self._settings_received, timeout=10)
        parsed = urlparse(url)
        authority = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        stream_id = self._quic.get_next_available_stream_id()
        response = {
            "done": asyncio.get_running_loop().create_future(),
            "headers": [],
            "body": bytearray(),
        }
        self._responses[stream_id] = response
        self._http.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"GET"),
                (b":scheme", parsed.scheme.encode("ascii")),
                (b":authority", authority.encode("ascii")),
                (b":path", path.encode("ascii")),
                (b"user-agent", b"incursa-aioquic-http3-external-interop"),
            ],
            end_stream=True,
        )
        self.transmit()
        await response["done"]
        return response["headers"], bytes(response["body"])

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["headers"].extend(http_event.headers)
                    if http_event.stream_ended and not response["done"].done():
                        response["done"].set_result(None)
            elif isinstance(http_event, DataReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["body"].extend(http_event.data)
                    if http_event.stream_ended and not response["done"].done():
                        response["done"].set_result(None)

        if self._http._settings_received and not self._settings_received.done():
            self._settings_received.set_result(None)


async def main_async(args):
    parsed = urlparse(args.url)
    if parsed.scheme != "https":
        raise ValueError("URL must use https")

    port = parsed.port or 443
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
    )

    async with connect(
        parsed.hostname,
        port,
        configuration=configuration,
        create_protocol=Http3ClientProtocol,
    ) as protocol:
        headers, body = await protocol.get(args.url)

    status = None
    for name, value in headers:
        if name == b":status":
            status = int(value.decode("ascii"))
            break

    if status is None:
        raise RuntimeError("response did not include :status")

    if status != args.expect_status:
        raise RuntimeError(f"unexpected status {status}; expected {args.expect_status}")

    if args.expect_header_count_at_least is not None and len(headers) < args.expect_header_count_at_least:
        raise RuntimeError(
            f"unexpected header count {len(headers)}; expected at least {args.expect_header_count_at_least}"
        )

    with open(args.output, "wb") as handle:
        handle.write(body)

    print(f"status={status} bytes={len(body)} output={args.output}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("output")
    parser.add_argument("--expect-status", type=int, default=200)
    parser.add_argument("--expect-header-count-at-least", type=int)
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
