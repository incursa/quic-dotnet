using System.Net;
using System.Net.Security;
using System.Diagnostics.CodeAnalysis;
using System.Security.Authentication;
using Incursa.Quic;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Http3.Client;

internal static class Program
{
    private const int InvalidArgumentsExitCode = 2;
    private const int DefaultPort = 443;
    private const int DefaultMaxInboundBidirectionalStreams = 100;
    private const int DefaultMaxInboundUnidirectionalStreams = 10;
    private const int DefaultExpectedStatusCode = 200;
    private const int OptionNameAndValueArgumentCount = 2;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length < 2)
        {
            await Console.Error.WriteLineAsync(
                "Usage: Incursa.Quic.Http3.Client <url> <output-path> [--expect-status <status>] [--strict-fin]");
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
                default:
                    await Console.Error.WriteLineAsync($"Unknown argument: {args[index]}");
                    return InvalidArgumentsExitCode;
            }
        }

        try
        {
            IPEndPoint remoteEndPoint = await ResolveRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            QuicClientConnectionOptions connectionOptions = CreateClientOptions(requestUri, remoteEndPoint);
            Http3Response response = await Http3Client.GetAsync(
                connectionOptions,
                requestUri,
                new Http3ClientOptions
                {
                    UserAgent = "incursa-quic-http3-external-interop",
                    CompleteResponseOnContentLength = completeResponseOnContentLength,
                }).ConfigureAwait(false);

            if (response.StatusCode != expectedStatusCode)
            {
                await Console.Error.WriteLineAsync(
                    $"Unexpected status code {response.StatusCode}; expected {expectedStatusCode}.");
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
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync(ex.ToString());
            return 1;
        }
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
}
