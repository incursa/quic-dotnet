# Minimal HTTP/3 client interop

This note covers the initial `Incursa.Quic.Http3.Http3Client` slice. The client opens QUIC with ALPN `h3`, creates the HTTP/3 control stream plus QPACK encoder and decoder streams, sends SETTINGS, and sends one GET request with QPACK static/literal field section encoding.

## Current client limits

- No QPACK dynamic table references are emitted.
- QPACK encoder and decoder streams are opened but no dynamic instructions are sent.
- Request bodies, trailers, and server push are not supported by this minimal client API.
- Response HEADERS and DATA are read from the request stream until FIN.

## aioquic smoke test

Start an aioquic HTTP/3 server with a local certificate:

```powershell
python -m aioquic.quic.tools.http3_server --certificate cert.pem --private-key key.pem --host 127.0.0.1 --port 4433
```

Run a small .NET harness that creates `QuicClientConnectionOptions` for `127.0.0.1:4433`, sets `SslClientAuthenticationOptions.ApplicationProtocols` to `SslApplicationProtocol.Http3`, trusts the test certificate, and calls:

```csharp
Http3Response response = await Http3Client.GetAsync(options, new Uri("https://localhost:4433/"));
```

Expected result: status code `200`, decoded response headers, body bytes, and `StreamCompleted == true`.

## quiche or nghttp3 smoke test

Run either server with ALPN `h3`, TLS 1.3, and a certificate trusted by the test harness:

```powershell
quiche-server --listen 127.0.0.1:4433 --cert cert.pem --key key.pem --root www
```

```powershell
nghttp3-server 127.0.0.1 4433 key.pem cert.pem
```

Use the same .NET harness shape as the aioquic test. Keep server push and dynamic QPACK disabled or unused for this milestone.
