namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessRunner
{
    private const int UnsupportedExitCode = 127;

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
        _ = certificatePath;
        _ = privateKeyPath;

        return settings.Role switch
        {
            InteropHarnessRole.Client => RunClient(settings, stdout),
            InteropHarnessRole.Server => RunServer(settings, stdout),
            _ => 1,
        };
    }

    private static IQuicDiagnosticsSink CreateDiagnosticsSink(InteropHarnessEnvironment settings)
    {
        return string.IsNullOrWhiteSpace(settings.QlogDirectory)
            ? QuicNullDiagnosticsSink.Instance
            : new InteropHarnessPlaceholderDiagnosticsSink(settings.QlogDirectory!);
    }

    private static int RunClient(InteropHarnessEnvironment settings, TextWriter stdout)
    {
        return ReturnUnsupported(settings, stdout, "client");
    }

    private static int RunServer(InteropHarnessEnvironment settings, TextWriter stdout)
    {
        return ReturnUnsupported(settings, stdout, "server");
    }

    private static int ReturnUnsupported(InteropHarnessEnvironment settings, TextWriter stdout, string roleName)
    {
        stdout.WriteLine(
            $"interop harness: role={roleName}, testcase={settings.TestCase}, requestCount={settings.Requests.Count} is currently unsupported.");
        return UnsupportedExitCode;
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
