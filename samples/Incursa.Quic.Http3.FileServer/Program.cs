// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Incursa.Qpack;
using Incursa.Quic;
using Incursa.Quic.Http3;
using Incursa.Quic.Qlog;

namespace Incursa.Quic.Http3.FileServer;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 2;
    private const int DefaultPort = 4433;
    private const int DefaultListenBacklog = 128;
    private const int DefaultMaxInboundBidirectionalStreams = 100;
    private const int DefaultMaxInboundUnidirectionalStreams = 10;
    private const int InteropReceiveWindowBytes = 16 * 1024 * 1024;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 3)
        {
            await Console.Error.WriteLineAsync("Usage: Incursa.Quic.Http3.FileServer <root-directory> <certificate-pem> <private-key-pem> [port] [--websocket-proof]");
            return InvalidArgumentsExitCode;
        }

        string rootDirectory = Path.GetFullPath(args[0]);
        if (!Directory.Exists(rootDirectory))
        {
            await Console.Error.WriteLineAsync($"Root directory does not exist: {rootDirectory}");
            return InvalidArgumentsExitCode;
        }

        string certificatePath = Path.GetFullPath(args[1]);
        string privateKeyPath = Path.GetFullPath(args[2]);
        int port = args.Length >= 4 && int.TryParse(args[3], out int parsedPort) ? parsedPort : DefaultPort;
        bool enableWebSocketProof = args.Any(static arg => string.Equals(arg, "--websocket-proof", StringComparison.Ordinal));

        using X509Certificate2 certificate = X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);
        FileRouteHandler handler = new(rootDirectory);
        QuicListenerOptions listenerOptions = CreateListenerOptions(port, certificate);
        Http3ServerOptions http3Options = CreateHttp3Options(enableWebSocketProof);
        await Console.Out.WriteLineAsync(
            $"http3-server-diagnostic runningInDocker={IsRunningInDocker().ToString().ToLowerInvariant()} configuredListenEndPoint={listenerOptions.ListenEndPoint} address={listenerOptions.ListenEndPoint.Address} port={listenerOptions.ListenEndPoint.Port} addressFamily={listenerOptions.ListenEndPoint.AddressFamily}");
        if (IsRunningInDocker() && IPAddress.IsLoopback(listenerOptions.ListenEndPoint.Address))
        {
            await Console.Error.WriteLineAsync("http3-server-diagnostic warning=server-bind-is-loopback-inside-docker");
        }

        QuicQlogCapture? qlogCapture = CreateQlogCapture("server-http3");
        using Timer? qlogSnapshotTimer = CreateQlogSnapshotTimer(qlogCapture, "server-http3");

        await using Http3Server server = qlogCapture is null
            ? await Http3Server.ListenAsync(listenerOptions, handler, http3Options)
            : Http3Server.Attach(
                await qlogCapture.ListenAsync(listenerOptions),
                handler,
                AttachDiagnostics(http3Options, new QuicQlogHttp3DiagnosticsSink(qlogCapture, isServer: true)));
        using CancellationTokenSource shutdown = new();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            shutdown.Cancel();
        };

        await Console.Out.WriteLineAsync($"Serving {rootDirectory} on https://localhost:{port}/ over HTTP/3.");
        try
        {
            await server.ServeAsync(shutdown.Token);
        }
        finally
        {
            TryWriteQlog(qlogCapture, "server-http3");
        }

        return 0;
    }

    private static Http3ServerOptions CreateHttp3Options(bool enableWebSocketProof)
    {
        Http3ServerOptions options = new();
        if (!enableWebSocketProof)
        {
            return options;
        }

        options.Settings = new Http3Settings(enableConnectProtocol: 1);
        options.WebSocketHandler = new ProofWebSocketHandler();
        options.WebSocketAcceptResponseHeadersSelector = static request =>
        {
            string offered = request.Headers.FirstOrDefault(static header => header.Name == "sec-websocket-protocol").Value;
            return string.IsNullOrWhiteSpace(offered)
                ? []
                : [new QPackFieldLine("sec-websocket-protocol", "proof.v1")];
        };
        return options;
    }

    private static Http3ServerOptions AttachDiagnostics(Http3ServerOptions source, IHttp3DiagnosticsSink diagnosticsSink)
    {
        source.DiagnosticsSink = diagnosticsSink;
        return source;
    }

    private static QuicQlogCapture? CreateQlogCapture(string title)
    {
        string? qlogDirectory = Environment.GetEnvironmentVariable("QLOGDIR");
        return string.IsNullOrWhiteSpace(qlogDirectory)
            ? null
            : new QuicQlogCapture(title, $"HTTP/3 sample qlog for {title}.");
    }

    private static void TryWriteQlog(QuicQlogCapture? capture, string fileStem)
    {
        if (capture is null || !capture.HasTraces)
        {
            return;
        }

        string? qlogDirectory = Environment.GetEnvironmentVariable("QLOGDIR");
        if (string.IsNullOrWhiteSpace(qlogDirectory))
        {
            return;
        }

        Directory.CreateDirectory(qlogDirectory);
        string outputPath = Path.Combine(qlogDirectory, $"{fileStem}-{Guid.NewGuid():N}.qlog");
        using FileStream stream = File.Create(outputPath);
        capture.WriteJson(stream, indented: true);
    }

    private static Timer? CreateQlogSnapshotTimer(QuicQlogCapture? capture, string fileStem)
    {
        if (capture is null)
        {
            return null;
        }

        return new Timer(
            static state =>
            {
                (QuicQlogCapture Capture, string FileStem) item = ((QuicQlogCapture, string))state!;
                TryWriteQlog(item.Capture, item.FileStem);
            },
            (capture, fileStem),
            TimeSpan.FromSeconds(2),
            TimeSpan.FromSeconds(2));
    }

    private static QuicListenerOptions CreateListenerOptions(int port, X509Certificate2 certificate)
    {
        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.Any, port),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = DefaultListenBacklog,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
            {
                MaxInboundBidirectionalStreams = DefaultMaxInboundBidirectionalStreams,
                MaxInboundUnidirectionalStreams = DefaultMaxInboundUnidirectionalStreams,
                InitialReceiveWindowSizes = CreateInteropReceiveWindowSizes(),
                ServerAuthenticationOptions = new SslServerAuthenticationOptions
                {
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
                    EnabledSslProtocols = SslProtocols.Tls13,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    ServerCertificate = certificate,
                },
            }),
        };
    }

    private static QuicReceiveWindowSizes CreateInteropReceiveWindowSizes()
    {
        return new QuicReceiveWindowSizes
        {
            Connection = InteropReceiveWindowBytes,
            LocallyInitiatedBidirectionalStream = InteropReceiveWindowBytes,
            RemotelyInitiatedBidirectionalStream = InteropReceiveWindowBytes,
            UnidirectionalStream = InteropReceiveWindowBytes,
        };
    }

    private static bool IsRunningInDocker()
    {
        string? dotnetContainer = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");
        return string.Equals(dotnetContainer, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(dotnetContainer, "1", StringComparison.Ordinal)
            || File.Exists("/.dockerenv");
    }
}

internal sealed class ProofWebSocketHandler : IHttp3WebSocketHandler
{
    public async ValueTask HandleAsync(Http3WebSocketTunnelContext context, CancellationToken cancellationToken = default)
    {
        await context.PingAsync("server-proof"u8.ToArray(), cancellationToken).ConfigureAwait(false);

        while (true)
        {
            Http3WebSocketMessage? message = await context.ReadMessageAsync(cancellationToken).ConfigureAwait(false);
            if (message is null)
            {
                return;
            }

            switch (message.Opcode)
            {
                case Http3WebSocketOpcode.Text:
                    string text = Encoding.UTF8.GetString(message.Payload.Span);
                    await context.WriteMessageAsync(
                        Http3WebSocketOpcode.Text,
                        Encoding.UTF8.GetBytes("echo:" + text),
                        cancellationToken).ConfigureAwait(false);
                    break;
                case Http3WebSocketOpcode.Binary:
                    await context.WriteMessageAsync(
                        Http3WebSocketOpcode.Binary,
                        message.Payload,
                        cancellationToken).ConfigureAwait(false);
                    break;
                case Http3WebSocketOpcode.Ping:
                    await context.EchoPingAsync(message, cancellationToken).ConfigureAwait(false);
                    break;
                case Http3WebSocketOpcode.Close:
                    await context.EchoCloseAsync(message, cancellationToken).ConfigureAwait(false);
                    return;
            }
        }
    }
}

internal sealed class FileRouteHandler : IHttp3RequestHandler
{
    private readonly string rootDirectory;
    private const int ManyHeaderCount = 64;
    private const int FixtureByteModulo = 251;
    private static readonly byte[] SplitDataBody = CreatePatternBytes(4096);
    private static readonly byte[] CancellationBody = CreatePatternBytes(128 * 1024);

    internal FileRouteHandler(string rootDirectory)
    {
        this.rootDirectory = rootDirectory;
    }

    public async ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        if (request.Method != "GET")
        {
            return new Http3ServerResponse(405, ReadOnlyMemory<byte>.Empty);
        }

        string requestPath = Uri.UnescapeDataString(request.Path.Split('?', 2)[0]);
        if (StringComparer.Ordinal.Equals(requestPath, "/many-headers.txt"))
        {
            byte[] manyHeadersBody = "many headers http3 fixture"u8.ToArray();
            return new Http3ServerResponse(200, manyHeadersBody, CreateManyHeaders(manyHeadersBody.Length));
        }

        if (StringComparer.Ordinal.Equals(requestPath, "/split-data.bin"))
        {
            return new Http3ServerResponse(
                200,
                SplitDataBody,
                [
                    new QPackFieldLine("content-type", "application/octet-stream"),
                    new QPackFieldLine("content-length", SplitDataBody.Length.ToString()),
                ],
                dataFramePayloadSize: 17);
        }

        if (StringComparer.Ordinal.Equals(requestPath, "/cancel.bin"))
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
            return new Http3ServerResponse(
                200,
                CancellationBody,
                [
                    new QPackFieldLine("content-type", "application/octet-stream"),
                    new QPackFieldLine("content-length", CancellationBody.Length.ToString()),
                ],
                dataFramePayloadSize: 31);
        }

        if (StringComparer.Ordinal.Equals(requestPath, "/goaway.txt"))
        {
            byte[] goAwayBody = "goaway http3 fixture"u8.ToArray();
            return new Http3ServerResponse(
                200,
                goAwayBody,
                [
                    new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                    new QPackFieldLine("content-length", goAwayBody.Length.ToString()),
                ],
                sendGoAwayAfterResponse: true);
        }

        if (StringComparer.Ordinal.Equals(requestPath, "/close-in-flight.bin"))
        {
            byte[] closeBody = CreatePatternBytes(8192);
            return new Http3ServerResponse(
                200,
                closeBody,
                [
                    new QPackFieldLine("content-type", "application/octet-stream"),
                    new QPackFieldLine("content-length", closeBody.Length.ToString()),
                ],
                dataFramePayloadSize: 19,
                closeConnectionAfterResponse: true);
        }

        string relativePath = requestPath.TrimStart('/');
        if (string.IsNullOrEmpty(relativePath))
        {
            relativePath = "index.html";
        }

        string filePath = Path.GetFullPath(Path.Combine(rootDirectory, relativePath.Replace('/', Path.DirectorySeparatorChar)));
        if (!filePath.StartsWith(rootDirectory, StringComparison.OrdinalIgnoreCase) || !File.Exists(filePath))
        {
            return new Http3ServerResponse(
                404,
                "Not Found"u8.ToArray(),
                [new QPackFieldLine("content-type", "text/plain")]);
        }

        byte[] body = await File.ReadAllBytesAsync(filePath, cancellationToken);
        return new Http3ServerResponse(
            200,
            body,
            [
                new QPackFieldLine("content-type", GetContentType(filePath)),
                new QPackFieldLine("content-length", body.Length.ToString()),
            ]);
    }

    private static string GetContentType(string filePath)
    {
        return Path.GetExtension(filePath).ToLowerInvariant() switch
        {
            ".css" => "text/css",
            ".gif" => "image/gif",
            ".htm" or ".html" => "text/html; charset=utf-8",
            ".jpg" or ".jpeg" => "image/jpeg",
            ".js" => "text/javascript",
            ".json" => "application/json",
            ".png" => "image/png",
            ".txt" => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
    }

    private static IReadOnlyList<QPackFieldLine> CreateManyHeaders(int bodyLength)
    {
        List<QPackFieldLine> headers =
        [
            new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
            new QPackFieldLine("content-length", bodyLength.ToString()),
        ];

        for (int index = 0; index < ManyHeaderCount; index++)
        {
            headers.Add(new QPackFieldLine($"x-incursa-header-{index:00}", $"value-{index:00}"));
        }

        return headers;
    }

    private static byte[] CreatePatternBytes(int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = (byte)(index % FixtureByteModulo);
        }

        return bytes;
    }
}
