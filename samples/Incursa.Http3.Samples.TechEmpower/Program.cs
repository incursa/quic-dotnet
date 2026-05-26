using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Incursa.Qpack;
using Incursa.Quic;
using Incursa.Quic.Http3;

namespace Incursa.Http3.Samples.TechEmpower;

internal static class Program
{
    private const int DefaultPort = 4433;
    private const int DefaultListenBacklog = 512;
    private const int DefaultMaxInboundBidirectionalStreams = 512;
    private const int DefaultMaxInboundUnidirectionalStreams = 16;
    private const int ReceiveWindowBytes = 16 * 1024 * 1024;

    public static async Task<int> Main(string[] args)
    {
        int port = ParsePort(args);
        using X509Certificate2 certificate = CreateSelfSignedCertificate();
        await using Http3Server server = await Http3Server.ListenAsync(
            CreateListenerOptions(port, certificate),
            new TechEmpowerHandler()).ConfigureAwait(false);

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

        await Console.Out.WriteLineAsync($"Serving Incursa HTTP/3 TechEmpower-shaped sample on https://localhost:{port}/").ConfigureAwait(false);
        await server.ServeAsync(shutdown.Token).ConfigureAwait(false);
        return 0;
    }

    private static int ParsePort(string[] args)
    {
        for (int index = 0; index < args.Length; index++)
        {
            if (args[index] == "--port" && index + 1 < args.Length && int.TryParse(args[index + 1], out int port))
            {
                return port;
            }
        }

        return DefaultPort;
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
                InitialReceiveWindowSizes = new QuicReceiveWindowSizes
                {
                    Connection = ReceiveWindowBytes,
                    LocallyInitiatedBidirectionalStream = ReceiveWindowBytes,
                    RemotelyInitiatedBidirectionalStream = ReceiveWindowBytes,
                    UnidirectionalStream = ReceiveWindowBytes,
                },
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

    private static X509Certificate2 CreateSelfSignedCertificate()
    {
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
        byte[] pfxBytes = certificate.Export(X509ContentType.Pkcs12);
        return X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            (string?)null,
            X509KeyStorageFlags.Exportable);
    }
}

public sealed class TechEmpowerHandler : IHttp3RequestHandler
{
    private const int StatusOk = 200;
    private const int StatusNotFound = 404;
    private const int StatusMethodNotAllowed = 405;
    private const int StatusNotImplemented = 501;

    private static readonly HashSet<string> PlaceholderRoutes = new(StringComparer.Ordinal)
    {
        "/db",
        "/queries",
        "/fortunes",
        "/updates",
        "/cached-queries",
    };

    public ValueTask<Http3ServerResponse> HandleAsync(Http3Request request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();

        string path = StripQuery(request.Path);
        Http3ServerResponse response = request.Method == "GET"
            ? HandleGet(path)
            : Text(StatusMethodNotAllowed, "Method Not Allowed");
        return ValueTask.FromResult(response);
    }

    private static Http3ServerResponse HandleGet(string path)
    {
        if (path == "/plaintext")
        {
            return Payload(TechEmpowerPayloads.Plaintext, "text/plain");
        }

        if (path == "/json")
        {
            return Payload(TechEmpowerPayloads.Json, "application/json");
        }

        if (PlaceholderRoutes.Contains(path))
        {
            return Text(StatusNotImplemented, "This TechEmpower route is intentionally not implemented in the first HTTP/3 sample pass.");
        }

        return Text(StatusNotFound, "Not Found");
    }

    private static Http3ServerResponse Payload(ReadOnlyMemory<byte> body, string contentType)
    {
        return new Http3ServerResponse(
            StatusOk,
            body,
            [
                new QPackFieldLine("content-type", contentType),
                new QPackFieldLine("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
                new QPackFieldLine("date", DateTimeOffset.UtcNow.ToString("R", CultureInfo.InvariantCulture)),
                new QPackFieldLine("server", "Incursa.Http3"),
            ]);
    }

    private static Http3ServerResponse Text(int statusCode, string text)
    {
        byte[] body = System.Text.Encoding.UTF8.GetBytes(text);
        return new Http3ServerResponse(
            statusCode,
            body,
            [
                new QPackFieldLine("content-type", "text/plain; charset=utf-8"),
                new QPackFieldLine("content-length", body.Length.ToString(CultureInfo.InvariantCulture)),
                new QPackFieldLine("server", "Incursa.Http3"),
            ]);
    }

    private static string StripQuery(string requestTarget)
    {
        int queryIndex = requestTarget.IndexOf('?', StringComparison.Ordinal);
        return queryIndex < 0 ? requestTarget : requestTarget[..queryIndex];
    }
}

public static class TechEmpowerPayloads
{
    private static readonly byte[] PlaintextBytes = "Hello, World!"u8.ToArray();

    private static readonly byte[] JsonBytes = """{"message":"Hello, World!"}"""u8.ToArray();

    public static ReadOnlyMemory<byte> Plaintext => PlaintextBytes;

    public static ReadOnlyMemory<byte> Json => JsonBytes;
}
