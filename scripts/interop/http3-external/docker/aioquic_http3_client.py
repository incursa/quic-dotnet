import argparse
import asyncio
import os
import ssl
import sys
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from aioquic.quic.logger import QuicFileLogger


class Http3ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._responses = {}
        self._settings_received = asyncio.get_running_loop().create_future()
        self._debug = os.environ.get("AIOQUIC_HTTP3_DEBUG") not in (None, "", "0", "false", "False")

    def _debug_print(self, message):
        if self._debug:
            print(message, file=sys.stderr)

    async def get(self, url, timeout):
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
            "content_length": None,
        }
        self._responses[stream_id] = response
        self._debug_print(f"request stream={stream_id} url={url} timeout={timeout}")
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
        await asyncio.wait_for(response["done"], timeout=timeout)
        return response["headers"], bytes(response["body"])

    def _maybe_finish_response(self, response, stream_ended):
        if response["done"].done():
            return

        content_length = response["content_length"]
        if content_length is not None and len(response["body"]) >= content_length:
            self._debug_print(
                f"response complete by content-length bytes={len(response['body'])} "
                f"content_length={content_length} stream_ended={stream_ended}"
            )
            response["done"].set_result(None)
        elif stream_ended:
            self._debug_print(
                f"response complete by FIN bytes={len(response['body'])} "
                f"content_length={content_length} stream_ended={stream_ended}"
            )
            response["done"].set_result(None)

    def quic_event_received(self, event):
        if self._debug:
            if isinstance(event, ConnectionTerminated):
                self._debug_print(
                    f"quic event=ConnectionTerminated "
                    f"error_code={event.error_code} "
                    f"frame_type={event.frame_type} "
                    f"reason={event.reason_phrase}"
                )
            elif hasattr(event, "stream_id"):
                self._debug_print(
                    f"quic event={event.__class__.__name__} "
                    f"stream={getattr(event, 'stream_id', '?')} "
                    f"length={getattr(event, 'data', b'') and len(getattr(event, 'data', b'')) or 0} "
                    f"end_stream={getattr(event, 'end_stream', '?')}"
                )
            else:
                self._debug_print(f"quic event={event.__class__.__name__}")
        for http_event in self._http.handle_event(event):
            if self._debug:
                self._debug_print(
                    f"http event={http_event.__class__.__name__} "
                    f"stream={getattr(http_event, 'stream_id', '?')} "
                    f"stream_ended={getattr(http_event, 'stream_ended', '?')}"
                )
            if isinstance(http_event, HeadersReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["headers"].extend(http_event.headers)
                    for name, value in http_event.headers:
                        if name == b"content-length":
                            try:
                                response["content_length"] = int(value.decode("ascii"))
                            except ValueError:
                                response["content_length"] = None
                            break
                    self._debug_print(
                        f"headers stream={http_event.stream_id} count={len(response['headers'])} "
                        f"content_length={response['content_length']} stream_ended={http_event.stream_ended}"
                    )
                    self._maybe_finish_response(response, http_event.stream_ended)
            elif isinstance(http_event, DataReceived):
                response = self._responses.get(http_event.stream_id)
                if response is not None:
                    response["body"].extend(http_event.data)
                    self._debug_print(
                        f"data stream={http_event.stream_id} chunk={len(http_event.data)} "
                        f"total={len(response['body'])} content_length={response['content_length']} "
                        f"stream_ended={http_event.stream_ended}"
                    )
                    self._maybe_finish_response(response, http_event.stream_ended)

        if self._http._settings_received and not self._settings_received.done():
            self._debug_print("settings received")
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
    qlog_dir = os.environ.get("QLOGDIR")
    if qlog_dir:
        os.makedirs(qlog_dir, exist_ok=True)
        configuration.quic_logger = QuicFileLogger(qlog_dir)

    secrets_log_file = None
    sslkeylogfile = os.environ.get("SSLKEYLOGFILE")
    if sslkeylogfile:
        os.makedirs(os.path.dirname(sslkeylogfile), exist_ok=True)
        secrets_log_file = open(sslkeylogfile, "a", encoding="utf-8")
        configuration.secrets_log_file = secrets_log_file

    try:
        async with connect(
            parsed.hostname,
            port,
            configuration=configuration,
            create_protocol=Http3ClientProtocol,
        ) as protocol:
            headers, body = await protocol.get(args.url, args.timeout)
    finally:
        if secrets_log_file is not None:
            secrets_log_file.close()

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
    parser.add_argument("--timeout", type=float, default=20.0)
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
