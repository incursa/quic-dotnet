import argparse
import asyncio
import hashlib
import json
import os
import secrets
import ssl
import struct
import sys
from urllib.parse import urlparse

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived
from aioquic.quic.logger import QuicFileLogger


OPCODE_TEXT = 0x1
OPCODE_BINARY = 0x2
OPCODE_CLOSE = 0x8
OPCODE_PING = 0x9
OPCODE_PONG = 0xA


def write_frame(opcode, payload=b"", masked=False):
    first = 0x80 | opcode
    payload_length = len(payload)
    header = bytearray([first])
    mask_bit = 0x80 if masked else 0
    if payload_length <= 125:
        header.append(mask_bit | payload_length)
    elif payload_length <= 0xFFFF:
        header.append(mask_bit | 126)
        header.extend(struct.pack("!H", payload_length))
    else:
        header.append(mask_bit | 127)
        header.extend(struct.pack("!Q", payload_length))

    if not masked:
        return bytes(header) + payload

    masking_key = secrets.token_bytes(4)
    masked_payload = bytes(value ^ masking_key[index % 4] for index, value in enumerate(payload))
    return bytes(header) + masking_key + masked_payload


class WebSocketFrameReader:
    def __init__(self):
        self._buffer = bytearray()

    def feed(self, data):
        self._buffer.extend(data)
        messages = []
        while True:
            if len(self._buffer) < 2:
                return messages

            first = self._buffer[0]
            second = self._buffer[1]
            final = (first & 0x80) != 0
            opcode = first & 0x0F
            masked = (second & 0x80) != 0
            length = second & 0x7F
            offset = 2
            if length == 126:
                if len(self._buffer) < offset + 2:
                    return messages
                length = struct.unpack("!H", self._buffer[offset : offset + 2])[0]
                offset += 2
            elif length == 127:
                if len(self._buffer) < offset + 8:
                    return messages
                length = struct.unpack("!Q", self._buffer[offset : offset + 8])[0]
                offset += 8

            masking_key = None
            if masked:
                if len(self._buffer) < offset + 4:
                    return messages
                masking_key = self._buffer[offset : offset + 4]
                offset += 4

            if len(self._buffer) < offset + length:
                return messages

            payload = bytes(self._buffer[offset : offset + length])
            del self._buffer[: offset + length]
            if masked:
                payload = bytes(value ^ masking_key[index % 4] for index, value in enumerate(payload))
            if not final:
                raise RuntimeError("fragmented server frames are not expected in this proof")
            messages.append((opcode, payload))


class Http3WebSocketClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._settings_received = asyncio.get_running_loop().create_future()
        self._response_received = asyncio.get_running_loop().create_future()
        self._message_queue = asyncio.Queue()
        self._reader = WebSocketFrameReader()
        self._stream_id = None
        self._response_headers = []
        self._status = None
        self._debug = os.environ.get("AIOQUIC_HTTP3_DEBUG") not in (None, "", "0", "false", "False")

    @property
    def status(self):
        return self._status

    @property
    def response_headers(self):
        return self._response_headers

    def _debug_print(self, message):
        if self._debug:
            print(message, file=sys.stderr)

    async def open_websocket(self, url, timeout):
        await asyncio.wait_for(self._settings_received, timeout=timeout)
        parsed = urlparse(url)
        authority = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        self._stream_id = self._quic.get_next_available_stream_id()
        self._http.send_headers(
            stream_id=self._stream_id,
            headers=[
                (b":method", b"CONNECT"),
                (b":protocol", b"websocket"),
                (b":scheme", parsed.scheme.encode("ascii")),
                (b":authority", authority.encode("ascii")),
                (b":path", path.encode("utf-8")),
                (b"user-agent", b"incursa-aioquic-rfc9220-external-proof"),
                (b"sec-websocket-protocol", b"proof.v1, fallback"),
            ],
            end_stream=False,
        )
        self.transmit()
        await asyncio.wait_for(self._response_received, timeout=timeout)
        if self._status is None or self._status < 200 or self._status > 299:
            raise RuntimeError(f"unexpected WebSocket CONNECT status {self._status}")

    async def read_message(self, timeout):
        return await asyncio.wait_for(self._message_queue.get(), timeout=timeout)

    def write_message(self, opcode, payload=b""):
        if self._stream_id is None:
            raise RuntimeError("WebSocket stream is not open")
        self._quic.send_stream_data(self._stream_id, write_frame(opcode, payload, masked=True), end_stream=False)
        self.transmit()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self._debug_print(
                f"quic terminated error_code={event.error_code} frame_type={event.frame_type} reason={event.reason_phrase}"
            )
        if isinstance(event, StreamDataReceived) and event.stream_id == self._stream_id and self._response_received.done():
            for message in self._reader.feed(event.data):
                self._message_queue.put_nowait(message)
            return

        for http_event in self._http.handle_event(event):
            if isinstance(http_event, HeadersReceived) and http_event.stream_id == self._stream_id:
                self._response_headers.extend(http_event.headers)
                for name, value in http_event.headers:
                    if name == b":status":
                        self._status = int(value.decode("ascii"))
                        break
                if not self._response_received.done():
                    self._response_received.set_result(None)

        if self._http._settings_received and not self._settings_received.done():
            self._settings_received.set_result(None)


async def run_proof(protocol, url, timeout):
    await protocol.open_websocket(url, timeout)

    opcode, payload = await protocol.read_message(timeout)
    if opcode != OPCODE_PING or payload != b"server-proof":
        raise RuntimeError(f"unexpected server ping opcode={opcode} payload={payload!r}")
    protocol.write_message(OPCODE_PONG, payload)

    protocol.write_message(OPCODE_PING, b"client-proof")
    opcode, payload = await protocol.read_message(timeout)
    if opcode != OPCODE_PONG or payload != b"client-proof":
        raise RuntimeError(f"unexpected client ping echo opcode={opcode} payload={payload!r}")

    protocol.write_message(OPCODE_TEXT, b"aioquic external text")
    opcode, payload = await protocol.read_message(timeout)
    if opcode != OPCODE_TEXT or payload != b"echo:aioquic external text":
        raise RuntimeError(f"unexpected text echo opcode={opcode} payload={payload!r}")

    binary_payload = bytes(index % 251 for index in range(6000))
    protocol.write_message(OPCODE_BINARY, binary_payload)
    opcode, payload = await protocol.read_message(timeout)
    if opcode != OPCODE_BINARY or payload != binary_payload:
        raise RuntimeError("unexpected binary echo")
    binary_echo = payload

    close_payload = struct.pack("!H", 1000) + b"done"
    protocol.write_message(OPCODE_CLOSE, close_payload)
    opcode, payload = await protocol.read_message(timeout)
    if opcode != OPCODE_CLOSE or payload != close_payload:
        raise RuntimeError(f"unexpected close echo opcode={opcode} payload={payload!r}")

    return {
        "status": "passed",
        "evidenceClass": "local-external-aioquic-peer",
        "url": url,
        "statusCode": protocol.status,
        "responseHeaders": [
            {"name": name.decode("ascii", errors="replace"), "value": value.decode("utf-8", errors="replace")}
            for name, value in protocol.response_headers
        ],
        "proofScope": [
            "HTTP/3 Extended CONNECT from aioquic client to Incursa server",
            "accepted response metadata",
            "server ping and aioquic client pong",
            "aioquic client ping and server pong echo",
            "text message echo",
            "6000-byte binary echo",
            "aioquic client close and server close echo",
        ],
        "binaryPayloadLength": len(binary_payload),
        "binaryPayloadSha256": hashlib.sha256(binary_payload).hexdigest().upper(),
        "binaryEchoSha256": hashlib.sha256(binary_echo).hexdigest().upper(),
        "close": {"statusCode": 1000, "reason": "done"},
    }


async def main_async(args):
    parsed = urlparse(args.url)
    if parsed.scheme != "https":
        raise ValueError("URL must use https")

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

    port = parsed.port or 443
    try:
        async with connect(
            parsed.hostname,
            port,
            configuration=configuration,
            create_protocol=Http3WebSocketClientProtocol,
        ) as protocol:
            result = await run_proof(protocol, args.url, args.timeout)
    finally:
        if secrets_log_file is not None:
            secrets_log_file.close()

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")

    print(f"websocketProofStatus=passed evidenceClass=local-external-aioquic-peer status={result['statusCode']} output={args.output}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("output")
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
