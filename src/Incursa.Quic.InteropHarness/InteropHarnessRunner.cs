using Incursa.Quic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessRunner
{
    private const int UnsupportedExitCode = 127;
    private const int DefaultHandshakePort = 443;

    internal static int Run(System.Collections.IDictionary environment, TextWriter stdout, TextWriter stderr)
    {
        return Run(environment, stdout, stderr, InteropHarnessEnvironment.CertificatePath, InteropHarnessEnvironment.PrivateKeyPath);
    }

    internal static int Run(
        System.Collections.IDictionary environment,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(stdout);
        ArgumentNullException.ThrowIfNull(stderr);

        if (!InteropHarnessEnvironment.TryCreate(environment, out InteropHarnessEnvironment? settingsCandidate, out string? errorMessage) ||
            settingsCandidate is null)
        {
            stderr.WriteLine(errorMessage);
            return 1;
        }

        InteropHarnessEnvironment settings = settingsCandidate;
        IQuicDiagnosticsSink diagnostics = CreateDiagnosticsSink(settings);
        _ = diagnostics;

        return settings.Role switch
        {
            InteropHarnessRole.Client => RunClient(settings, stdout, stderr),
            InteropHarnessRole.Server => RunServer(settings, stdout, stderr, certificatePath, privateKeyPath),
            _ => 1,
        };
    }

    private static IQuicDiagnosticsSink CreateDiagnosticsSink(InteropHarnessEnvironment settings)
    {
        return string.IsNullOrWhiteSpace(settings.QlogDirectory)
            ? QuicNullDiagnosticsSink.Instance
            : new InteropHarnessPlaceholderDiagnosticsSink(settings.QlogDirectory!);
    }

    private static int RunClient(InteropHarnessEnvironment settings, TextWriter stdout, TextWriter stderr)
    {
        return settings.TestCase switch
        {
            "handshake" => RunHandshakeClientAsync(settings, stdout, stderr).GetAwaiter().GetResult(),
            _ => ReturnUnsupported(settings, stdout, "client"),
        };
    }

    private static int RunServer(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        return settings.TestCase switch
        {
            "handshake" => RunHandshakeServerAsync(settings, stdout, stderr, certificatePath, privateKeyPath).GetAwaiter().GetResult(),
            _ => ReturnUnsupported(settings, stdout, "server"),
        };
    }

    private static async Task<int> RunHandshakeClientAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr)
    {
        try
        {
            if (!QuicConnection.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC client bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!TryGetHandshakeRequestUri(settings, out Uri? requestUri, out string? errorMessage) ||
                requestUri is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            IPEndPoint remoteEndPoint = await ResolveHandshakeRemoteEndPointAsync(requestUri).ConfigureAwait(false);
            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} connecting to {remoteEndPoint}.");

            QuicClientConnectionOptions clientOptions = new()
            {
                RemoteEndPoint = remoteEndPoint,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    AllowRenegotiation = false,
                    AllowTlsResume = true,
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
                    EnabledSslProtocols = SslProtocols.Tls13,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    RemoteCertificateValidationCallback = (_, _, _, errors) =>
                    {
                        WriteLineAndFlush(stdout, $"interop harness: role=client, testcase=handshake, certificate errors={errors}.");
                        return errors == SslPolicyErrors.RemoteCertificateChainErrors;
                    },
                },
            };

            await using QuicConnection connection = await QuicConnection.ConnectAsync(clientOptions).ConfigureAwait(false);

            WriteLineAndFlush(
                stdout,
                $"interop harness: role=client, testcase=handshake, requestCount={settings.Requests.Count} completed managed client bootstrap.");
            return 0;
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=client, testcase=handshake failed: {ex.Message}");
            return 1;
        }
    }

    private static async Task<int> RunHandshakeServerAsync(
        InteropHarnessEnvironment settings,
        TextWriter stdout,
        TextWriter stderr,
        string certificatePath,
        string privateKeyPath)
    {
        try
        {
            if (!QuicListener.IsSupported)
            {
                WriteLineAndFlush(stderr, "interop harness: managed QUIC listener bootstrap is not supported in this runtime.");
                return 1;
            }

            if (!TryGetHandshakeRequestUri(settings, out Uri? requestUri, out string? errorMessage) ||
                requestUri is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!InteropTlsMaterials.TryLoad(certificatePath, privateKeyPath, out InteropTlsMaterials? materials, out errorMessage) ||
                materials is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            if (!materials.TryCreateServerCertificate(out X509Certificate2? serverCertificate, out errorMessage) ||
                serverCertificate is null)
            {
                WriteLineAndFlush(stderr, errorMessage ?? string.Empty);
                return 1;
            }

            using (serverCertificate)
            {
                IPEndPoint listenEndPoint = await ResolveHandshakeListenEndPointAsync(requestUri).ConfigureAwait(false);
                QuicListenerOptions listenerOptions = new()
                {
                    ListenEndPoint = listenEndPoint,
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
                    ListenBacklog = 1,
                    ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(CreateSupportedServerOptions(serverCertificate)),
                };

                await using QuicListener listener = await QuicListener.ListenAsync(listenerOptions).ConfigureAwait(false);
                Task<QuicConnection> acceptTask = listener.AcceptConnectionAsync().AsTask();
                await Task.Yield();
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=handshake, requestCount={settings.Requests.Count} listening on {listenEndPoint}.");

                await using QuicConnection connection = await acceptTask.ConfigureAwait(false);
                WriteLineAndFlush(
                    stdout,
                    $"interop harness: role=server, testcase=handshake, requestCount={settings.Requests.Count} completed managed listener bootstrap.");
                return 0;
            }
        }
        catch (Exception ex)
        {
            WriteLineAndFlush(stderr, $"interop harness: role=server, testcase=handshake failed: {ex.Message}");
            return 1;
        }
    }

    private static int ReturnUnsupported(InteropHarnessEnvironment settings, TextWriter stdout, string roleName)
    {
        stdout.WriteLine(
            $"interop harness: role={roleName}, testcase={settings.TestCase}, requestCount={settings.Requests.Count} is currently unsupported.");
        return UnsupportedExitCode;
    }

    private static void WriteLineAndFlush(TextWriter writer, string message)
    {
        writer.WriteLine(message);
        writer.Flush();
    }

    private static bool TryGetHandshakeRequestUri(
        InteropHarnessEnvironment settings,
        out Uri? requestUri,
        out string? errorMessage)
    {
        if (settings.Requests.Count == 0)
        {
            requestUri = null;
            errorMessage = "REQUESTS must contain at least one URL for handshake dispatch.";
            return false;
        }

        string request = settings.Requests[0];
        if (!Uri.TryCreate(request, UriKind.Absolute, out requestUri) || requestUri is null)
        {
            errorMessage = $"REQUESTS entry '{request}' is not a valid absolute URL.";
            return false;
        }

        if (!string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            errorMessage = $"REQUESTS entry '{request}' must use https for handshake dispatch.";
            requestUri = null;
            return false;
        }

        errorMessage = null;
        return true;
    }

    private static async ValueTask<IPEndPoint> ResolveHandshakeRemoteEndPointAsync(Uri requestUri)
    {
        int port = requestUri.IsDefaultPort ? DefaultHandshakePort : requestUri.Port;

        if (IPAddress.TryParse(requestUri.Host, out IPAddress? remoteAddress))
        {
            return new IPEndPoint(remoteAddress, port);
        }

        IPAddress[] resolvedAddresses = await Dns.GetHostAddressesAsync(requestUri.Host).ConfigureAwait(false);
        IPAddress? selectedAddress = resolvedAddresses.FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetwork)
            ?? resolvedAddresses.FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetworkV6);

        if (selectedAddress is null)
        {
            throw new InvalidOperationException($"Unable to resolve handshake request host '{requestUri.Host}'.");
        }

        return new IPEndPoint(selectedAddress, port);
    }

    private static async ValueTask<IPEndPoint> ResolveHandshakeListenEndPointAsync(Uri requestUri)
    {
        int port = requestUri.IsDefaultPort ? DefaultHandshakePort : requestUri.Port;
        if (IPAddress.TryParse(requestUri.Host, out IPAddress? requestAddress))
        {
            return new IPEndPoint(requestAddress, port);
        }

        IPAddress[] resolvedAddresses = await Dns.GetHostAddressesAsync(requestUri.Host).ConfigureAwait(false);
        IPAddress? selectedAddress = resolvedAddresses.FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetwork)
            ?? resolvedAddresses.FirstOrDefault(static address => address.AddressFamily == AddressFamily.InterNetworkV6);

        if (selectedAddress is null)
        {
            throw new InvalidOperationException($"Unable to resolve handshake request host '{requestUri.Host}'.");
        }

        return new IPEndPoint(selectedAddress, port);
    }

    private static QuicServerConnectionOptions CreateSupportedServerOptions(X509Certificate2 serverCertificate)
    {
        return new QuicServerConnectionOptions
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ServerCertificate = serverCertificate,
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
        };
    }
}

internal sealed class InteropHarnessPlaceholderDiagnosticsSink : IQuicDiagnosticsSink
{
    public InteropHarnessPlaceholderDiagnosticsSink(string outputDirectory)
    {
        OutputDirectory = outputDirectory;
    }

    public string OutputDirectory { get; }

    public bool IsEnabled => true;

    public void Emit(QuicDiagnosticEvent diagnosticEvent)
    {
        _ = diagnosticEvent;
    }
}
