// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Incursa.Qpack;
using Incursa.Quic;
using Incursa.Quic.Http3;
using Incursa.Quic.Qlog;

namespace Incursa.Http3.Samples.ObjectStore;

internal static class Program
{
    private const int DefaultPort = 4433;
    private const int InvalidArgumentsExitCode = 2;
    private const int DefaultListenBacklog = 256;
    private const int DefaultMaxInboundBidirectionalStreams = 256;
    private const int DefaultMaxInboundUnidirectionalStreams = 16;
    private const int ReceiveWindowBytes = 32 * 1024 * 1024;

    public static async Task<int> Main(string[] args)
    {
        SampleHostOptions options;
        try
        {
            options = SampleHostOptions.Parse(args, DefaultPort);
        }
        catch (ArgumentException ex)
        {
            await Console.Error.WriteLineAsync(ex.Message).ConfigureAwait(false);
            await Console.Error.WriteLineAsync("Usage: Incursa.Http3.Samples.ObjectStore [--port 4433] [--cert cert.pem --key priv.key] [--max-upload-bytes 26214400]").ConfigureAwait(false);
            return InvalidArgumentsExitCode;
        }

        using X509Certificate2 certificate = options.CreateCertificate();
        ObjectStoreMetrics metrics = new();
        ObjectStoreHandler handler = new(new InMemoryUploadStore(), metrics, options.MaxUploadBytes);
        QuicListenerOptions listenerOptions = CreateListenerOptions(options.Port, certificate);
        QuicQlogCapture? qlogCapture = CreateQlogCapture();
        await using Http3Server server = qlogCapture is null
            ? await Http3Server.ListenAsync(
                listenerOptions,
                handler,
                new Http3ServerOptions { DiagnosticsSink = metrics }).ConfigureAwait(false)
            : Http3Server.Attach(
                await qlogCapture.ListenAsync(listenerOptions).ConfigureAwait(false),
                handler,
                new Http3ServerOptions
                {
                    DiagnosticsSink = new CompositeHttp3DiagnosticsSink(
                        metrics,
                        new ConsoleHttp3ErrorDiagnosticsSink(),
                        new QuicQlogHttp3DiagnosticsSink(qlogCapture, isServer: true)),
                });

        using CancellationTokenSource shutdown = new();
        int shutdownRequested = 0;
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            if (Interlocked.Exchange(ref shutdownRequested, 1) == 0)
            {
                shutdown.Cancel();
            }
        };

        await Console.Out.WriteLineAsync(BrowserLaunchInstructions.Create(options.Port, certificate)).ConfigureAwait(false);
        try
        {
            await server.ServeAsync(shutdown.Token).ConfigureAwait(false);
        }
        finally
        {
            TryWriteQlog(qlogCapture);
        }

        return 0;
    }

    private static QuicQlogCapture? CreateQlogCapture()
    {
        string? qlogDirectory = Environment.GetEnvironmentVariable("QLOGDIR");
        return string.IsNullOrWhiteSpace(qlogDirectory)
            ? null
            : new QuicQlogCapture(
                "Incursa HTTP/3 ObjectStore",
                "HTTP/3 sample qlog for the Incursa ObjectStore demo.");
    }

    private static void TryWriteQlog(QuicQlogCapture? capture)
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
        string outputPath = Path.Combine(qlogDirectory, $"objectstore-{Guid.NewGuid():N}.qlog");
        using FileStream stream = File.Create(outputPath);
        capture.WriteJson(stream, indented: true);
    }

    private static QuicListenerOptions CreateListenerOptions(int port, X509Certificate2 certificate)
    {
        return new QuicListenerOptions
        {
            ListenEndPoint = new IPEndPoint(IPAddress.IPv6Any, port),
            ApplicationProtocols = [SslApplicationProtocol.Http3],
            ListenBacklog = DefaultListenBacklog,
            ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions
            {
                MaxInboundBidirectionalStreams = DefaultMaxInboundBidirectionalStreams,
                MaxInboundUnidirectionalStreams = DefaultMaxInboundUnidirectionalStreams,
                InitialReceiveWindowSizes = CreateReceiveWindowSizes(),
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

    private static QuicReceiveWindowSizes CreateReceiveWindowSizes()
    {
        return new QuicReceiveWindowSizes
        {
            Connection = ReceiveWindowBytes,
            LocallyInitiatedBidirectionalStream = ReceiveWindowBytes,
            RemotelyInitiatedBidirectionalStream = ReceiveWindowBytes,
            UnidirectionalStream = ReceiveWindowBytes,
        };
    }
}

public static class BrowserLaunchInstructions
{
    private const int MaxTcpUdpPort = 65535;

    public static string Create(int port, X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        return Create(port, ComputeSubjectPublicKeyInfoSha256(certificate));
    }

    public static string Create(int port, string? certificateSpkiSha256)
    {
        if (port is <= 0 or > MaxTcpUdpPort)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        string url = string.Create(CultureInfo.InvariantCulture, $"https://localhost:{port}/");
        string spkiArgument = string.IsNullOrWhiteSpace(certificateSpkiSha256)
            ? "--ignore-certificate-errors"
            : string.Create(CultureInfo.InvariantCulture, $"--ignore-certificate-errors-spki-list={certificateSpkiSha256}");

        StringBuilder builder = new();
        builder.AppendLine(CultureInfo.InvariantCulture, $"Serving Incursa HTTP/3 ObjectStore on {url}");
        builder.AppendLine();
        builder.AppendLine("Browser note:");
        builder.AppendLine("  This sample listens on HTTP/3 over QUIC/UDP only. A normal HTTPS tab usually tries TCP first and can show ERR_CONNECTION_REFUSED.");
        builder.AppendLine(CultureInfo.InvariantCulture, $"  Launch a fresh browser profile with QUIC forced for localhost:{port} so the browser connects directly with HTTP/3.");
        builder.AppendLine();
        builder.AppendLine("PowerShell launch commands from the repository root:");
        builder.AppendLine("  Edge:");
        AppendChromiumCommand(
            builder,
            WindowsProgramFilesPath("Program Files", "Microsoft", "Edge", "Application", "msedge.exe"),
            ".artifacts\\http3-browser-debug\\edge-profile",
            port,
            spkiArgument,
            url);
        AppendChromiumCommand(
            builder,
            WindowsProgramFilesPath("Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
            ".artifacts\\http3-browser-debug\\edge-profile",
            port,
            spkiArgument,
            url);
        builder.AppendLine();
        builder.AppendLine("  Chrome:");
        AppendChromiumCommand(
            builder,
            WindowsProgramFilesPath("Program Files", "Google", "Chrome", "Application", "chrome.exe"),
            ".artifacts\\http3-browser-debug\\chrome-profile",
            port,
            spkiArgument,
            url);
        AppendChromiumCommand(
            builder,
            WindowsProgramFilesPath("Program Files (x86)", "Google", "Chrome", "Application", "chrome.exe"),
            ".artifacts\\http3-browser-debug\\chrome-profile",
            port,
            spkiArgument,
            url);
        builder.AppendLine("    $chrome = Join-Path $env:LOCALAPPDATA 'Google\\Chrome\\Application\\chrome.exe'; if (Test-Path $chrome) { & $chrome --new-window --enable-quic --origin-to-force-quic-on=localhost:" + port.ToString(CultureInfo.InvariantCulture) + " " + spkiArgument + " --no-proxy-server --user-data-dir=.artifacts\\http3-browser-debug\\chrome-profile " + url + " }");
        builder.AppendLine();
        builder.AppendLine("  Firefox:");
        builder.AppendLine("    Firefox does not provide a Chromium-style --origin-to-force-quic-on switch. This command is only useful after you configure a Firefox profile to allow HTTP/3 for this localhost origin and trust the sample certificate:");
        AppendFirefoxCommand(builder, WindowsProgramFilesPath("Program Files", "Mozilla Firefox", "firefox.exe"), url);
        AppendFirefoxCommand(builder, WindowsProgramFilesPath("Program Files (x86)", "Mozilla Firefox", "firefox.exe"), url);
        return builder.ToString();
    }

    private static void AppendChromiumCommand(
        StringBuilder builder,
        string executablePath,
        string profilePath,
        int port,
        string certificateArgument,
        string url)
    {
        builder.Append("    if (Test-Path '");
        builder.Append(executablePath);
        builder.Append("') { & '");
        builder.Append(executablePath);
        builder.Append("' --new-window --enable-quic --origin-to-force-quic-on=localhost:");
        builder.Append(port.ToString(CultureInfo.InvariantCulture));
        builder.Append(' ');
        builder.Append(certificateArgument);
        builder.Append(" --no-proxy-server --user-data-dir=");
        builder.Append(profilePath);
        builder.Append(' ');
        builder.Append(url);
        builder.AppendLine(" }");
    }

    private static void AppendFirefoxCommand(StringBuilder builder, string executablePath, string url)
    {
        builder.Append("    if (Test-Path '");
        builder.Append(executablePath);
        builder.Append("') { & '");
        builder.Append(executablePath);
        builder.Append("' -new-window ");
        builder.Append(url);
        builder.AppendLine(" }");
    }

    private static string WindowsProgramFilesPath(string programFilesDirectory, params string[] segments)
    {
        string path = Path.Combine("C:" + Path.DirectorySeparatorChar, programFilesDirectory);
        foreach (string segment in segments)
        {
            path = Path.Combine(path, segment);
        }

        return path;
    }

    private static string? ComputeSubjectPublicKeyInfoSha256(X509Certificate2 certificate)
    {
        byte[] subjectPublicKeyInfo;

        using (ECDsa? ecdsa = certificate.GetECDsaPublicKey())
        {
            if (ecdsa is not null)
            {
                subjectPublicKeyInfo = ecdsa.ExportSubjectPublicKeyInfo();
                return Convert.ToBase64String(SHA256.HashData(subjectPublicKeyInfo));
            }
        }

        using (RSA? rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
                return Convert.ToBase64String(SHA256.HashData(subjectPublicKeyInfo));
            }
        }

        return null;
    }
}

public sealed class ObjectStoreHandler : IHttp3RequestHandler
{
    private const long DefaultMaxUploadBytes = 25L * 1024 * 1024;
    private const int StatusOk = 200;
    private const int StatusBadRequest = 400;
    private const int StatusNotFound = 404;
    private const int StatusMethodNotAllowed = 405;
    private const int StatusConflict = 409;
    private const int StatusPayloadTooLarge = 413;
    private const int StatusInternalServerError = 500;
    private const int StreamIterationCount = 20;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly byte[] PlaintextBody = "Hello, World!"u8.ToArray();
    private static readonly byte[] JsonBody = """{"message":"Hello, World!"}"""u8.ToArray();
    private readonly InMemoryUploadStore uploads;
    private readonly ObjectStoreMetrics metrics;
    private readonly long maxUploadBytes;

    public ObjectStoreHandler(InMemoryUploadStore uploads, ObjectStoreMetrics metrics, long maxUploadBytes = DefaultMaxUploadBytes)
    {
        this.uploads = uploads ?? throw new ArgumentNullException(nameof(uploads));
        this.metrics = metrics ?? throw new ArgumentNullException(nameof(metrics));
        this.maxUploadBytes = maxUploadBytes > 0 ? maxUploadBytes : throw new ArgumentOutOfRangeException(nameof(maxUploadBytes));
    }

    public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        RequestTarget target = RequestTarget.Parse(request.Path);
        Http3ServerResponse response = request.Method switch
        {
            "GET" => HandleGet(request, target, cancellationToken),
            "POST" when target.Path == "/api/files" => HandleFileUpload(request),
            _ => Text(StatusMethodNotAllowed, "Method Not Allowed"),
        };
        return ValueTask.FromResult(response);
    }

    public static RequestTarget MatchTarget(string requestTarget)
    {
        return RequestTarget.Parse(requestTarget);
    }

    private Http3ServerResponse HandleGet(Http3Request request, RequestTarget target, CancellationToken cancellationToken)
    {
        if (target.Path == "/")
        {
            return Html(IndexHtml);
        }

        if (target.Path == "/assets/app.css")
        {
            return TextAsset("text/css; charset=utf-8", AppCss);
        }

        if (target.Path == "/assets/app.js")
        {
            return TextAsset("text/javascript; charset=utf-8", AppJs);
        }

        if (target.Path == "/assets/sample.txt")
        {
            return TextAsset("text/plain; charset=utf-8", SampleText);
        }

        if (target.Path == "/assets/incursa.svg")
        {
            return SvgAsset("incursa-logo-dark.svg");
        }

        if (target.Path == "/assets/incursa-icon.svg")
        {
            return SvgAsset("incursa-icon-dark.svg");
        }

        if (target.Path == "/assets/incursa-logo-indigo.svg")
        {
            return SvgAsset("incursa-logo-indigo.svg");
        }

        if (target.Path == "/assets/incursa-logo-white.svg")
        {
            return SvgAsset("incursa-logo-white.svg");
        }

        if (target.Path == "/assets/incursa-icon-indigo.svg")
        {
            return SvgAsset("incursa-icon-indigo.svg");
        }

        if (target.Path == "/assets/incursa-icon-white.svg")
        {
            return SvgAsset("incursa-icon-white.svg");
        }

        if (target.Path == "/api/status")
        {
            return Json(CreateStatusPayload());
        }

        if (target.Path == "/api/headers")
        {
            return Json(CreateHeadersPayload(request, target));
        }

        if (target.Path.StartsWith("/api/files/", StringComparison.Ordinal))
        {
            string id = Uri.UnescapeDataString(target.Path["/api/files/".Length..]);
            if (uploads.TryGet(id, out StoredUpload? upload))
            {
                return Bytes(StatusOk, upload!.Content, upload.ContentType);
            }

            return Text(StatusNotFound, "Not Found");
        }

        if (target.Path == "/api/stream")
        {
            return Http3ServerResponse.CreateStreaming(
                StatusOk,
                CreateStream(cancellationToken),
                [
                    new QPackFieldLine("content-type", "text/event-stream; charset=utf-8"),
                    new QPackFieldLine("cache-control", "no-store"),
                ]);
        }

        if (target.Path.StartsWith("/api/errors/", StringComparison.Ordinal))
        {
            return ErrorResponse(target.Path);
        }

        if (target.Path == "/plaintext")
        {
            return Bytes(StatusOk, PlaintextBody, "text/plain");
        }

        if (target.Path == "/json")
        {
            return Bytes(StatusOk, JsonBody, "application/json");
        }

        return Text(StatusNotFound, "Not Found");
    }

    private Http3ServerResponse HandleFileUpload(Http3Request request)
    {
        if (request.Body.Length > maxUploadBytes)
        {
            return Text(StatusPayloadTooLarge, $"Upload exceeds {maxUploadBytes.ToString(CultureInfo.InvariantCulture)} bytes.");
        }

        string contentType = TryGetHeader(request, "content-type") ?? "application/octet-stream";
        StoredUpload upload = uploads.Add(request.Body.Span, contentType);
        return Json(new
        {
            id = upload.Id,
            byteCount = upload.Content.Length,
            sha256 = upload.Sha256,
            contentType = upload.ContentType,
        });
    }

    private object CreateStatusPayload()
    {
        return new
        {
            server = "Incursa.Http3",
            protocol = "h3",
            utc = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            processId = Environment.ProcessId,
            activeConnections = metrics.ActiveConnections,
            activeRequests = metrics.ActiveRequests,
        };
    }

    private static object CreateHeadersPayload(Http3Request request, RequestTarget target)
    {
        return new
        {
            method = request.Method,
            path = target.Path,
            queryString = target.QueryString,
            headers = request.Headers
                .Where(static header => !header.Name.StartsWith(':'))
                .GroupBy(static header => header.Name, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    static group => group.Key,
                    static group => group.Select(static header => header.Value).ToArray(),
                    StringComparer.OrdinalIgnoreCase),
        };
    }

    private static Http3ServerResponse ErrorResponse(string path)
    {
        string codeText = path["/api/errors/".Length..];
        return int.TryParse(codeText, NumberStyles.None, CultureInfo.InvariantCulture, out int code) &&
            (code == StatusBadRequest || code == StatusNotFound || code == StatusConflict || code == StatusInternalServerError)
            ? Text(code, $"Requested error {code.ToString(CultureInfo.InvariantCulture)}")
            : Text(StatusBadRequest, "Unsupported error code.");
    }

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> CreateStream(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        for (int index = 1; index <= StreamIterationCount; index++)
        {
            string line = string.Create(
                CultureInfo.InvariantCulture,
                $"data: Incursa HTTP/3 stream {index} utc={DateTimeOffset.UtcNow:O}\n\n");
            yield return Encoding.UTF8.GetBytes(line);
            await Task.Delay(TimeSpan.FromMilliseconds(250), cancellationToken).ConfigureAwait(false);
        }
    }

    private static string? TryGetHeader(Http3Request request, string name)
    {
        foreach (QPackFieldLine header in request.Headers)
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(header.Name, name))
            {
                return header.Value;
            }
        }

        return null;
    }

    private static Http3ServerResponse Json(object value)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        return Bytes(StatusOk, body, "application/json");
    }

    private static Http3ServerResponse Html(string value)
    {
        return TextAsset("text/html; charset=utf-8", value);
    }

    private static Http3ServerResponse Text(int statusCode, string value)
    {
        byte[] body = Encoding.UTF8.GetBytes(value);
        return new Http3ServerResponse(
            statusCode,
            body,
            [
                new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                new QPackFieldLine("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private static Http3ServerResponse TextAsset(string contentType, string value)
    {
        return Bytes(StatusOk, Encoding.UTF8.GetBytes(value), contentType);
    }

    private static Http3ServerResponse SvgAsset(string fileName)
    {
        return Bytes(StatusOk, LoadEmbeddedAsset(fileName), "image/svg+xml");
    }

    private static byte[] LoadEmbeddedAsset(string fileName)
    {
        string resourceName = string.Create(
            CultureInfo.InvariantCulture,
            $"Incursa.Http3.Samples.ObjectStore.Assets.{fileName}");
        Assembly assembly = typeof(ObjectStoreHandler).Assembly;
        using Stream? stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            throw new InvalidOperationException($"The embedded sample asset '{fileName}' was not found.");
        }

        using MemoryStream buffer = new();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static Http3ServerResponse Bytes(int statusCode, ReadOnlyMemory<byte> body, string contentType)
    {
        return new Http3ServerResponse(
            statusCode,
            body,
            [
                new QPackFieldLine("content-type", contentType),
                new QPackFieldLine("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
            ]);
    }

    private const string IndexHtml = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Incursa HTTP/3 ObjectStore</title>
  <link rel="stylesheet" href="/assets/app.css">
  <script src="/assets/app.js" defer></script>
</head>
<body>
  <main>
    <img class="brand-logo" src="/assets/incursa.svg" width="249" height="41" alt="Incursa">
    <h1>Incursa HTTP/3 ObjectStore</h1>
    <p>This page is served by Incursa HTTP/3 over the repository QUIC transport.</p>
    <section class="grid" aria-label="HTTP/3 stream assets">
      <article class="card">
        <h2>Status API</h2>
        <pre id="status">Loading status...</pre>
      </article>
      <article class="card">
        <h2>Text Asset</h2>
        <pre id="sample-text">Loading sample.txt...</pre>
      </article>
      <article class="card">
        <h2>JavaScript</h2>
        <p id="asset-status">Loading app.js...</p>
      </article>
    </section>
  </main>
</body>
</html>
""";

    private const string AppCss = """
body { font-family: system-ui, sans-serif; margin: 2rem; background: #f7f7f4; color: #1d2525; }
main { max-width: 920px; }
.brand-logo { display: block; width: min(249px, 70vw); height: auto; margin-bottom: 2rem; }
h1 { margin-bottom: .25rem; }
.grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 1.5rem; }
.card { border: 1px solid #cbd8d4; border-radius: 8px; background: #ffffff; padding: 1rem; }
.card h2 { font-size: 1rem; margin: 0 0 .75rem; }
pre { min-height: 7rem; margin: 0; padding: 1rem; background: #101818; color: #d8f6e4; overflow: auto; }
#asset-status { margin: 0; font-weight: 600; color: #0b6f86; }
""";

    private const string AppJs = """
window.incursaObjectStoreReady = false;
window.incursaObjectStoreScriptLoaded = true;
document.getElementById('asset-status').textContent = 'app.js running over Incursa HTTP/3';

window.incursaObjectStoreAssetProof = Promise.all([
  fetch('/api/status').then(response => response.json()),
  fetch('/assets/sample.txt').then(response => response.text()),
  fetch('/assets/app.css').then(response => response.text()),
  fetch('/assets/incursa.svg').then(response => response.text())
])
  .then(([status, sampleText]) => {
    window.incursaObjectStoreStatus = status;
    window.incursaObjectStoreSampleText = sampleText;
    document.getElementById('status').textContent = JSON.stringify(status, null, 2);
    document.getElementById('sample-text').textContent = sampleText;
    document.getElementById('asset-status').textContent = 'assets loaded over Incursa HTTP/3';
    window.incursaObjectStoreReady = true;
    return { status, sampleText };
  })
  .catch(error => {
    window.incursaObjectStoreError = error.message;
    document.getElementById('asset-status').textContent = error.message;
    window.incursaObjectStoreReady = false;
    throw error;
  });
""";

    private const string SampleText = "This small text asset is loaded over a separate HTTP/3 request stream.\n";

}

public sealed class InMemoryUploadStore
{
    private readonly Dictionary<string, StoredUpload> uploads = new(StringComparer.Ordinal);
    private readonly object gate = new();

    public StoredUpload Add(ReadOnlySpan<byte> content, string contentType)
    {
        string id = Guid.NewGuid().ToString("N");
        byte[] bytes = content.ToArray();
        string hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        StoredUpload upload = new(id, bytes, contentType, hash);
        lock (gate)
        {
            uploads[id] = upload;
        }

        return upload;
    }

    public bool TryGet(string id, out StoredUpload? upload)
    {
        lock (gate)
        {
            return uploads.TryGetValue(id, out upload);
        }
    }
}

public sealed record StoredUpload(string Id, byte[] Content, string ContentType, string Sha256);

public sealed class ObjectStoreMetrics : IHttp3DiagnosticsSink
{
    private int activeConnections;
    private int activeRequests;

    public bool IsEnabled => true;

    public int ActiveConnections => Volatile.Read(ref activeConnections);

    public int ActiveRequests => Volatile.Read(ref activeRequests);

    public void Emit(Http3DiagnosticEvent diagnosticEvent)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEvent);
        switch (diagnosticEvent.Kind)
        {
            case Http3DiagnosticKind.ConnectionStarted:
                Interlocked.Increment(ref activeConnections);
                break;
            case Http3DiagnosticKind.ConnectionClosed:
                Interlocked.Decrement(ref activeConnections);
                break;
            case Http3DiagnosticKind.RequestStarted:
                Interlocked.Increment(ref activeRequests);
                break;
            case Http3DiagnosticKind.RequestCompleted:
                Interlocked.Decrement(ref activeRequests);
                break;
        }
    }
}

internal sealed class CompositeHttp3DiagnosticsSink : IHttp3DiagnosticsSink
{
    private readonly IHttp3DiagnosticsSink[] sinks;

    public CompositeHttp3DiagnosticsSink(params IHttp3DiagnosticsSink[] sinks)
    {
        this.sinks = sinks ?? throw new ArgumentNullException(nameof(sinks));
    }

    public bool IsEnabled => sinks.Any(static sink => sink.IsEnabled);

    public void Emit(Http3DiagnosticEvent diagnosticEvent)
    {
        foreach (IHttp3DiagnosticsSink sink in sinks)
        {
            if (sink.IsEnabled)
            {
                sink.Emit(diagnosticEvent);
            }
        }
    }
}

internal sealed class ConsoleHttp3ErrorDiagnosticsSink : IHttp3DiagnosticsSink
{
    public bool IsEnabled => true;

    public void Emit(Http3DiagnosticEvent diagnosticEvent)
    {
        if (diagnosticEvent.Kind != Http3DiagnosticKind.Error)
        {
            return;
        }

        Console.Error.WriteLine(
            "HTTP/3 error {0}: {1}",
            diagnosticEvent.ErrorCode ?? "unknown",
            diagnosticEvent.Message ?? string.Empty);
    }
}

public sealed record RequestTarget(string Path, string QueryString)
{
    public static RequestTarget Parse(string requestTarget)
    {
        ArgumentNullException.ThrowIfNull(requestTarget);
        int queryIndex = requestTarget.IndexOf('?', StringComparison.Ordinal);
        if (queryIndex < 0)
        {
            return new RequestTarget(string.IsNullOrEmpty(requestTarget) ? "/" : requestTarget, string.Empty);
        }

        string path = queryIndex == 0 ? "/" : requestTarget[..queryIndex];
        return new RequestTarget(path, requestTarget[(queryIndex + 1)..]);
    }
}

internal sealed class SampleHostOptions
{
    private const long DefaultMaxUploadBytes = 25L * 1024 * 1024;
    private const int OptionValueWidth = 2;

    private SampleHostOptions(int port, string? certificatePath, string? privateKeyPath, long maxUploadBytes)
    {
        Port = port;
        CertificatePath = certificatePath;
        PrivateKeyPath = privateKeyPath;
        MaxUploadBytes = maxUploadBytes;
    }

    public int Port { get; }

    public string? CertificatePath { get; }

    public string? PrivateKeyPath { get; }

    public long MaxUploadBytes { get; }

    public static SampleHostOptions Parse(string[] args, int defaultPort)
    {
        int port = defaultPort;
        string? certificatePath = null;
        string? privateKeyPath = null;
        long maxUploadBytes = DefaultMaxUploadBytes;

        int index = 0;
        while (index < args.Length)
        {
            switch (args[index])
            {
                case "--port" when index + 1 < args.Length && int.TryParse(args[index + 1], out int parsedPort):
                    port = parsedPort;
                    index += OptionValueWidth;
                    break;
                case "--cert" when index + 1 < args.Length:
                    certificatePath = Path.GetFullPath(args[index + 1]);
                    index += OptionValueWidth;
                    break;
                case "--key" when index + 1 < args.Length:
                    privateKeyPath = Path.GetFullPath(args[index + 1]);
                    index += OptionValueWidth;
                    break;
                case "--max-upload-bytes" when index + 1 < args.Length && long.TryParse(args[index + 1], NumberStyles.None, CultureInfo.InvariantCulture, out long parsedMaxUploadBytes):
                    maxUploadBytes = parsedMaxUploadBytes;
                    index += OptionValueWidth;
                    break;
                default:
                    throw new ArgumentException($"Unknown or invalid argument: {args[index]}");
            }
        }

        if ((certificatePath is null) != (privateKeyPath is null))
        {
            throw new ArgumentException("Both --cert and --key must be supplied together.");
        }

        return new SampleHostOptions(port, certificatePath, privateKeyPath, maxUploadBytes);
    }

    public X509Certificate2 CreateCertificate()
    {
        if (CertificatePath is not null && PrivateKeyPath is not null)
        {
            using X509Certificate2 loadedCertificate = X509Certificate2.CreateFromPemFile(CertificatePath, PrivateKeyPath);
            return ToExportableCertificate(loadedCertificate);
        }

        using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=localhost", ecdsa, HashAlgorithmName.SHA256);
        SubjectAlternativeNameBuilder subjectAlternativeNames = new();
        subjectAlternativeNames.AddDnsName("localhost");
        subjectAlternativeNames.AddIpAddress(IPAddress.Loopback);
        subjectAlternativeNames.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));
        return ToExportableCertificate(certificate);
    }

    private static X509Certificate2 ToExportableCertificate(X509Certificate2 certificate)
    {
        byte[] pfxBytes = certificate.Export(X509ContentType.Pkcs12);
        return X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            (string?)null,
            X509KeyStorageFlags.Exportable);
    }
}
