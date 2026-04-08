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
    string? SslKeyLogFile)
{
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

        if (!TryParseRole(roleValue, out InteropHarnessRole role))
        {
            errorMessage = $"Unsupported ROLE value '{roleValue}'. Expected client or server.";
            return false;
        }

        if (!TryGetString(environment, "TESTCASE", out string? testCaseValue) || string.IsNullOrWhiteSpace(testCaseValue))
        {
            errorMessage = "TESTCASE must be set.";
            return false;
        }

        IReadOnlyList<string> requests = ParseRequests(GetString(environment, "REQUESTS"));
        settings = new InteropHarnessEnvironment(
            role,
            testCaseValue.Trim().ToLowerInvariant(),
            requests,
            GetString(environment, "QLOGDIR"),
            GetString(environment, "SSLKEYLOGFILE"));
        return true;
    }

    internal static bool TryParseRole(string value, out InteropHarnessRole role)
    {
        if (string.Equals(value, "client", StringComparison.OrdinalIgnoreCase))
        {
            role = InteropHarnessRole.Client;
            return true;
        }

        if (string.Equals(value, "server", StringComparison.OrdinalIgnoreCase))
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
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();
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
