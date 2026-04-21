using System.Collections;

namespace Incursa.Quic.InteropHarness;

internal enum InteropHarnessRole
{
    Client = 0,
    Server = 1,
}

internal sealed record InteropHarnessEnvironment(
    InteropHarnessRole Role,
    string TestCase,
    IReadOnlyList<string> Requests,
    string? QlogDirectory,
    string? SslKeyLogFile,
    ReadOnlyMemory<byte> LocalHandshakePrivateKey)
{
    private const int DeterministicHandshakePrivateKeyLength = 32;

    public const string WwwDirectory = "/www";

    public const string DownloadsDirectory = "/downloads";

    public const string CertificatePath = "/certs/cert.pem";

    public const string PrivateKeyPath = "/certs/priv.key";

    internal static bool TryCreate(System.Collections.IDictionary environment, out InteropHarnessEnvironment? settings, out string? errorMessage)
    {
        settings = null;
        errorMessage = null;

        if (!TryGetString(environment, "ROLE", out string? roleValue) || string.IsNullOrWhiteSpace(roleValue))
        {
            errorMessage = "ROLE must be set to client or server.";
            return false;
        }

        string normalizedRoleValue = roleValue.Trim();
        if (!TryParseRole(normalizedRoleValue, out InteropHarnessRole role))
        {
            errorMessage = $"Unsupported ROLE value '{normalizedRoleValue}'. Expected client or server.";
            return false;
        }

        if (!TryGetString(environment, "TESTCASE", out string? testCaseValue) || string.IsNullOrWhiteSpace(testCaseValue))
        {
            errorMessage = "TESTCASE must be set.";
            return false;
        }

        if (!TryGetOptionalLocalHandshakePrivateKey(environment, out byte[] localHandshakePrivateKey, out errorMessage))
        {
            return false;
        }

        IReadOnlyList<string> requests = ParseRequests(GetString(environment, "REQUESTS"));
        settings = new InteropHarnessEnvironment(
            role,
            testCaseValue.Trim().ToLowerInvariant(),
            requests,
            GetString(environment, "QLOGDIR"),
            GetString(environment, "SSLKEYLOGFILE"),
            localHandshakePrivateKey);
        return true;
    }

    internal static bool TryParseRole(string value, out InteropHarnessRole role)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            role = default;
            return false;
        }

        string normalizedValue = value.Trim();

        if (string.Equals(normalizedValue, "client", StringComparison.OrdinalIgnoreCase))
        {
            role = InteropHarnessRole.Client;
            return true;
        }

        if (string.Equals(normalizedValue, "server", StringComparison.OrdinalIgnoreCase))
        {
            role = InteropHarnessRole.Server;
            return true;
        }

        role = default;
        return false;
    }

    private static IReadOnlyList<string> ParseRequests(string? requestsValue)
    {
        if (string.IsNullOrWhiteSpace(requestsValue))
        {
            return Array.Empty<string>();
        }

        return requestsValue
            .Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();
    }

    private static bool TryGetOptionalLocalHandshakePrivateKey(
        IDictionary environment,
        out byte[] localHandshakePrivateKey,
        out string? errorMessage)
    {
        localHandshakePrivateKey = Array.Empty<byte>();
        errorMessage = null;

        string? localHandshakePrivateKeyHex = GetLocalHandshakePrivateKeyHex(environment);
        if (string.IsNullOrWhiteSpace(localHandshakePrivateKeyHex))
        {
            return true;
        }

        try
        {
            localHandshakePrivateKey = Convert.FromHexString(localHandshakePrivateKeyHex.Trim());
        }
        catch (FormatException)
        {
            errorMessage = "Deterministic local handshake key must be an even-length hexadecimal string.";
            return false;
        }

        if (localHandshakePrivateKey.Length != DeterministicHandshakePrivateKeyLength)
        {
            errorMessage = $"Deterministic local handshake key must decode to exactly {DeterministicHandshakePrivateKeyLength} bytes.";
            return false;
        }

        return true;
    }

    private static string? GetLocalHandshakePrivateKeyHex(IDictionary environment)
    {
        if (TryGetString(environment, "LOCAL_HANDSHAKE_PRIVATE_KEY_HEX", out string? directValue)
            && !string.IsNullOrWhiteSpace(directValue))
        {
            return directValue;
        }

        if (!TryGetString(environment, "CLIENT_PARAMS", out string? clientParams)
            || string.IsNullOrWhiteSpace(clientParams))
        {
            return null;
        }

        foreach (string token in clientParams.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            const string Prefix = "local_handshake_private_key_hex=";
            if (token.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                return token[Prefix.Length..];
            }
        }

        return null;
    }

    private static bool TryGetString(System.Collections.IDictionary environment, string name, out string? value)
    {
        object? candidate = environment[name];
        if (candidate is null)
        {
            value = null;
            return false;
        }

        value = candidate as string ?? candidate.ToString();
        return value is not null;
    }

    private static string? GetString(System.Collections.IDictionary environment, string name)
    {
        _ = TryGetString(environment, name, out string? value);
        return value;
    }
}
