using Incursa.Quic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Incursa.Quic.InteropHarness;

internal sealed class InteropHarnessPreflightPlanner
{
    private const int DefaultHandshakePort = 443;

    private readonly InteropHarnessEnvironment settings;
    private readonly TextWriter stdout;

    internal InteropHarnessPreflightPlanner(InteropHarnessEnvironment settings, TextWriter stdout)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(stdout);

        this.settings = settings;
        this.stdout = stdout;
    }

    internal string QlogFileStem => $"{settings.Role.ToString().ToLowerInvariant()}-{settings.TestCase}";

    internal InteropHarnessQlogCaptureScope? CreateQlogCaptureScope()
    {
        return InteropHarnessQlogCaptureScope.Create(settings, QlogFileStem);
    }

    internal bool TryGetDispatchRequestUri(
        out Uri? requestUri,
        out string? errorMessage,
        bool allowEmptyRequests = false)
    {
        if (settings.Requests.Count == 0)
        {
            requestUri = null;
            if (allowEmptyRequests)
            {
                errorMessage = null;
                return true;
            }

            errorMessage = "REQUESTS must contain at least one URL for testcase dispatch.";
            return false;
        }

        string request = settings.Requests[0];
        if (!Uri.TryCreate(request, UriKind.Absolute, out requestUri) || requestUri is null)
        {
            requestUri = null;
            errorMessage = $"REQUESTS entry '{request}' is not a valid absolute URL.";
            return false;
        }

        if (!string.Equals(requestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            errorMessage = $"REQUESTS entry '{request}' must use https for testcase dispatch.";
            requestUri = null;
            return false;
        }

        errorMessage = null;
        return true;
    }

    internal QuicClientConnectionOptions CreateSupportedClientOptions(
        IPEndPoint remoteEndPoint,
        string? targetHost = null)
    {
        return new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                AllowRenegotiation = false,
                AllowTlsResume = true,
                ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                TargetHost = string.IsNullOrWhiteSpace(targetHost) ? null : targetHost,
                RemoteCertificateValidationCallback = (_, _, _, errors) =>
                {
                    WriteLineAndFlush(
                        stdout,
                        $"interop harness: role=client, testcase={settings.TestCase}, certificate errors={errors}.");
                    return errors == SslPolicyErrors.RemoteCertificateChainErrors;
                },
            },
        };
    }

    internal static QuicServerConnectionOptions CreateSupportedServerOptions(X509Certificate2 serverCertificate)
    {
        return new QuicServerConnectionOptions
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = [InteropHarnessProtocols.QuicInterop],
                ServerCertificate = serverCertificate,
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            },
        };
    }

    internal static bool TryGetTransferPaths(
        Uri? requestUri,
        out string? relativePath,
        out string? sourcePath,
        out string? destinationPath,
        out string? errorMessage)
    {
        relativePath = null;
        sourcePath = null;
        destinationPath = null;

        if (requestUri is null)
        {
            if (!TryGetDefaultTransferRelativePath(out relativePath, out errorMessage) ||
                relativePath is null)
            {
                return false;
            }
        }
        else if (!TryGetTransferRelativePath(
            requestUri.AbsolutePath,
            requestUri.ToString(),
            out relativePath,
            out errorMessage) ||
            relativePath is null)
        {
            return false;
        }

        try
        {
            sourcePath = ResolveMountedPath(InteropHarnessEnvironment.WwwDirectory, relativePath);
            destinationPath = ResolveMountedPath(InteropHarnessEnvironment.DownloadsDirectory, relativePath);
            errorMessage = null;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException or PathTooLongException)
        {
            string requestDescription = requestUri?.ToString() ?? "(empty REQUESTS)";
            errorMessage = $"Unable to resolve transfer paths for '{requestDescription}': {ex.Message}";
            return false;
        }
    }

    internal static bool TryGetTransferPathsFromRequestTarget(
        string requestTarget,
        out string? relativePath,
        out string? sourcePath,
        out string? destinationPath,
        out string? errorMessage)
    {
        relativePath = null;
        sourcePath = null;
        destinationPath = null;

        if (string.IsNullOrWhiteSpace(requestTarget))
        {
            errorMessage = "HTTP/0.9 request target must not be empty.";
            return false;
        }

        string normalizedTarget = requestTarget.Trim();
        if (Uri.TryCreate(normalizedTarget, UriKind.Absolute, out Uri? requestUri) && requestUri is not null)
        {
            return TryGetTransferPaths(requestUri, out relativePath, out sourcePath, out destinationPath, out errorMessage);
        }

        int querySeparatorIndex = normalizedTarget.IndexOfAny(['?', '#']);
        string requestPath = querySeparatorIndex >= 0
            ? normalizedTarget[..querySeparatorIndex]
            : normalizedTarget;

        if (!TryGetTransferRelativePath(
            requestPath,
            normalizedTarget,
            out relativePath,
            out errorMessage) ||
            relativePath is null)
        {
            return false;
        }

        try
        {
            sourcePath = ResolveMountedPath(InteropHarnessEnvironment.WwwDirectory, relativePath);
            destinationPath = ResolveMountedPath(InteropHarnessEnvironment.DownloadsDirectory, relativePath);
            errorMessage = null;
            return true;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or NotSupportedException or PathTooLongException)
        {
            errorMessage = $"Unable to resolve transfer paths for '{normalizedTarget}': {ex.Message}";
            return false;
        }
    }

    internal static async ValueTask<IPEndPoint> ResolveHandshakeRemoteEndPointAsync(Uri requestUri)
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

    internal static async ValueTask<IPEndPoint> ResolveHandshakeListenEndPointAsync(Uri? requestUri)
    {
        if (requestUri is null)
        {
            return new IPEndPoint(IPAddress.Any, DefaultHandshakePort);
        }

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

    private static bool TryGetDefaultTransferRelativePath(
        out string? relativePath,
        out string? errorMessage)
    {
        string rootFullPath = Path.GetFullPath(InteropHarnessEnvironment.WwwDirectory);
        if (!Directory.Exists(rootFullPath))
        {
            relativePath = null;
            errorMessage = $"Unable to infer a transfer target because the mounted source root '{rootFullPath}' does not exist.";
            return false;
        }

        try
        {
            relativePath = Directory.EnumerateFiles(rootFullPath, "*", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(rootFullPath, path))
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or PathTooLongException)
        {
            relativePath = null;
            errorMessage = $"Unable to infer a transfer target from an empty REQUESTS list because the mounted source root '{rootFullPath}' could not be enumerated: {ex.Message}";
            return false;
        }

        if (relativePath is null)
        {
            errorMessage = $"Unable to infer a transfer target from an empty REQUESTS list because '{rootFullPath}' contains no files.";
            return false;
        }

        errorMessage = null;
        return true;
    }

    private static bool TryGetTransferRelativePath(
        string requestPath,
        string requestDescription,
        out string? relativePath,
        out string? errorMessage)
    {
        string normalizedRequestPath = Uri.UnescapeDataString(requestPath).Replace('\\', '/');
        string[] pathSegments = normalizedRequestPath.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (pathSegments.Length == 0)
        {
            relativePath = null;
            errorMessage = $"REQUESTS entry '{requestDescription}' must include a non-root path for transfer dispatch.";
            return false;
        }

        foreach (string segment in pathSegments)
        {
            if (segment is "." or "..")
            {
                relativePath = null;
                errorMessage = $"REQUESTS entry '{requestDescription}' must not escape the transfer mount roots.";
                return false;
            }

            if (segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            {
                relativePath = null;
                errorMessage = $"REQUESTS entry '{requestDescription}' contains an invalid transfer path segment '{segment}'.";
                return false;
            }
        }

        relativePath = Path.Combine(pathSegments);
        errorMessage = null;
        return true;
    }

    private static string ResolveMountedPath(string rootDirectory, string relativePath)
    {
        string rootFullPath = Path.GetFullPath(rootDirectory);
        string candidatePath = Path.GetFullPath(Path.Combine(rootFullPath, relativePath));
        string relativeToRoot = Path.GetRelativePath(rootFullPath, candidatePath);
        if (relativeToRoot is "." or ".." ||
            relativeToRoot.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Transfer target '{relativePath}' escapes the mounted root '{rootDirectory}'.");
        }

        return candidatePath;
    }

    private static void WriteLineAndFlush(TextWriter writer, string message)
    {
        writer.WriteLine(message);
        writer.Flush();
    }
}
