using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Incursa.Qpack;
using Incursa.Quic;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Http3.FileServer;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 2;
    private const int DefaultPort = 4433;
    private const int DefaultListenBacklog = 128;
    private const int DefaultMaxInboundBidirectionalStreams = 100;
    private const int DefaultMaxInboundUnidirectionalStreams = 10;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 3)
        {
            await Console.Error.WriteLineAsync("Usage: Incursa.Quic.Http3.FileServer <root-directory> <certificate-pem> <private-key-pem> [port]");
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

        using X509Certificate2 certificate = X509Certificate2.CreateFromPemFile(certificatePath, privateKeyPath);
        FileRouteHandler handler = new(rootDirectory);
        QuicListenerOptions listenerOptions = CreateListenerOptions(port, certificate);

        await using Http3Server server = await Http3Server.ListenAsync(listenerOptions, handler);
        using CancellationTokenSource shutdown = new();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            shutdown.Cancel();
        };

        await Console.Out.WriteLineAsync($"Serving {rootDirectory} on https://localhost:{port}/ over HTTP/3.");
        await server.ServeAsync(shutdown.Token);
        return 0;
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
}

internal sealed class FileRouteHandler : IHttp3RequestHandler
{
    private readonly string rootDirectory;

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

        string relativePath = Uri.UnescapeDataString(request.Path.Split('?', 2)[0]).TrimStart('/');
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
}
