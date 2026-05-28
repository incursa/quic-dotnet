// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Diagnostics.CodeAnalysis;
using System.Security.Authentication;
using Incursa.Quic;
using Incursa.Quic.Http3;
using Incursa.Quic.Qlog;

namespace Incursa.Quic.Http3.Client;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 2;
    private const int DefaultPort = 443;
    private const int DefaultMaxInboundBidirectionalStreams = 100;
    private const int DefaultMaxInboundUnidirectionalStreams = 10;
    private const int InteropReceiveWindowBytes = 16 * 1024 * 1024;
    private const int DefaultExpectedStatusCode = 200;
    private const int OptionNameAndValueArgumentCount = 2;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 2)
        {
            await Console.Error.WriteLineAsync(
                "Usage: Incursa.Quic.Http3.Client <url> <output-path> [--expect-status <status>] [--strict-fin] [--cancel-after-ms <milliseconds>] [--expect-header-count-at-least <count>]");
            return InvalidArgumentsExitCode;
        }

        if (!Uri.TryCreate(args[0], UriKind.Absolute, out Uri? requestUri) ||
            requestUri is null ||
            !string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            await Console.Error.WriteLineAsync("The URL must be an absolute https URI.");
            return InvalidArgumentsExitCode;
        }

        string outputPath = Path.GetFullPath(args[1]);
        int expectedStatusCode = DefaultExpectedStatusCode;
        bool completeResponseOnContentLength = true;
        int? cancelAfterMilliseconds = null;
        int? expectedMinimumHeaderCount = null;

        int index = 2;
        while (index < args.Length)
        {
            switch (args[index])
            {
                case "--expect-status" when index + 1 < args.Length && int.TryParse(args[index + 1], out int statusCode):
                    expectedStatusCode = statusCode;
                    index += OptionNameAndValueArgumentCount;
                    break;
                case "--strict-fin":
                    completeResponseOnContentLength = false;
                    index++;
                    break;
                case "--cancel-after-ms" when index + 1 < args.Length && int.TryParse(args[index + 1], out int cancelAfter):
                    cancelAfterMilliseconds = cancelAfter;
                    index += OptionNameAndValueArgumentCount;
                    break;
                case "--expect-header-count-at-least" when index + 1 < args.Length && int.TryParse(args[index + 1], out int headerCount):
                    expectedMinimumHeaderCount = headerCount;
                    index += OptionNameAndValueArgumentCount;
                    break;
                default:
                    await Console.Error.WriteLineAsync($"Unknown argument: {args[index]}");
                    return InvalidArgumentsExitCode;
            }
        }

        QuicQlogCapture? qlogCapture = null;
        using CancellationTokenSource? requestCancellation = cancelAfterMilliseconds.HasValue
            ? new CancellationTokenSource(TimeSpan.FromMilliseconds(cancelAfterMilliseconds.Value))
            : null;
        CancellationToken requestCancellationToken = requestCancellation?.Token ?? CancellationToken.None;
        try
        {
            IPEndPoint remoteEndPoint = await ResolveRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            await Console.Out.WriteLineAsync(
                $"http3-client-diagnostic runningInDocker={IsRunningInDocker().ToString().ToLowerInvariant()} targetUrl={requestUri} targetHost={requestUri.Host} targetPort={remoteEndPoint.Port} resolvedAddress={remoteEndPoint.Address} addressFamily={remoteEndPoint.AddressFamily}");
            if (IsRunningInDocker() && IsLoopbackHost(requestUri.Host))
            {
                await Console.Error.WriteLineAsync(
                    "http3-client-diagnostic warning=client-target-host-is-loopback-inside-docker");
            }

            QuicClientConnectionOptions connectionOptions = CreateClientOptions(requestUri, remoteEndPoint);
            qlogCapture = CreateQlogCapture("client-http3");
            using Timer? qlogSnapshotTimer = CreateQlogSnapshotTimer(qlogCapture, "client-http3");
            Http3Response response;
            if (qlogCapture is null)
            {
                response = await Http3Client.GetAsync(
                    connectionOptions,
                    requestUri,
                    CreateHttp3Options(completeResponseOnContentLength, null),
                    requestCancellationToken).ConfigureAwait(false);
            }
            else
            {
                await using QuicConnection connection = await qlogCapture.ConnectAsync(connectionOptions, requestCancellationToken).ConfigureAwait(false);
                await using Http3Client client = await Http3Client.AttachAsync(
                    connection,
                    CreateHttp3Options(
                        completeResponseOnContentLength,
                        new QuicQlogHttp3DiagnosticsSink(qlogCapture, isServer: false)),
                    requestCancellationToken).ConfigureAwait(false);
                response = await client.GetAsync(requestUri, requestCancellationToken).ConfigureAwait(false);
            }

            if (response.StatusCode != expectedStatusCode)
            {
                await Console.Error.WriteLineAsync(
                    $"Unexpected status code {response.StatusCode}; expected {expectedStatusCode}.");
                return 1;
            }

            if (expectedMinimumHeaderCount.HasValue && response.Headers.Count < expectedMinimumHeaderCount.Value)
            {
                await Console.Error.WriteLineAsync(
                    $"Unexpected header count {response.Headers.Count}; expected at least {expectedMinimumHeaderCount.Value}.");
                return 1;
            }

            string? outputDirectory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(outputDirectory))
            {
                Directory.CreateDirectory(outputDirectory);
            }

            await File.WriteAllBytesAsync(outputPath, response.Body).ConfigureAwait(false);
            await Console.Out.WriteLineAsync(
                $"status={response.StatusCode} bytes={response.Body.Length} streamCompleted={response.StreamCompleted.ToString().ToLowerInvariant()} output={outputPath}");
            return 0;
        }
        catch (OperationCanceledException) when (cancelAfterMilliseconds.HasValue)
        {
            await Console.Out.WriteLineAsync($"cancelled=true afterMs={cancelAfterMilliseconds.Value} output={outputPath}");
            return 0;
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.ToString());
            return 1;
        }
        finally
        {
            TryWriteQlog(qlogCapture, "client-http3");
        }
    }

    private static Http3ClientOptions CreateHttp3Options(
        bool completeResponseOnContentLength,
        IHttp3DiagnosticsSink? diagnosticsSink)
    {
        return new Http3ClientOptions
        {
            UserAgent = "incursa-quic-http3-external-interop",
            CompleteResponseOnContentLength = completeResponseOnContentLength,
            DiagnosticsSink = diagnosticsSink,
        };
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

    private static async ValueTask<IPEndPoint> ResolveRemoteEndPointAsync(Uri requestUri)
    {
        int port = requestUri.IsDefaultPort ? DefaultPort : requestUri.Port;
        if (IPAddress.TryParse(requestUri.Host, out IPAddress? address))
        {
            return new IPEndPoint(address, port);
        }

        IPAddress[] addresses = await Dns.GetHostAddressesAsync(requestUri.Host).ConfigureAwait(false);
        IPAddress? selected = addresses.FirstOrDefault(static candidate => candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault(static candidate => candidate.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6);

        return selected is not null
            ? new IPEndPoint(selected, port)
            : throw new InvalidOperationException($"Unable to resolve '{requestUri.Host}'.");
    }

    [SuppressMessage(
        "Security",
        "S4830:Enable server certificate validation on this SSL/TLS connection",
        Justification = "The external interop harness uses throwaway self-signed certificates generated per local run.")]
    private static QuicClientConnectionOptions CreateClientOptions(Uri requestUri, IPEndPoint remoteEndPoint)
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            MaxInboundBidirectionalStreams = DefaultMaxInboundBidirectionalStreams,
            MaxInboundUnidirectionalStreams = DefaultMaxInboundUnidirectionalStreams,
            InitialReceiveWindowSizes = CreateInteropReceiveWindowSizes(),
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                TargetHost = requestUri.Host,
                RemoteCertificateValidationCallback = (_, _, _, _) => true,
            },
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

    private static bool IsLoopbackHost(string host)
    {
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "127.0.0.1", StringComparison.Ordinal)
            || string.Equals(host, "::1", StringComparison.Ordinal)
            || string.Equals(host, "[::1]", StringComparison.Ordinal)
            || (IPAddress.TryParse(host, out IPAddress? address) && IPAddress.IsLoopback(address));
    }

    private static bool IsRunningInDocker()
    {
        string? dotnetContainer = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");
        return string.Equals(dotnetContainer, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(dotnetContainer, "1", StringComparison.Ordinal)
            || File.Exists("/.dockerenv");
    }
}
