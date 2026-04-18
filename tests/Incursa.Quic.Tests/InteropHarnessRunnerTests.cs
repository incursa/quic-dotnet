using System.Collections;
using System.IO;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessRunnerTests
{
    [Theory]
    [InlineData("client")]
    [InlineData("server")]
    public void UnsupportedTestcasesReturn127ForEitherRole(string role)
    {
        IDictionary environment = CreateEnvironment(role, "multipath");

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(127, exitCode);
        Assert.Equal(
            $"interop harness: role={role}, testcase=multipath, requestCount=0 is currently unsupported.{Environment.NewLine}",
            stdout.ToString());
        Assert.Equal(string.Empty, stderr.ToString());
    }

    [Theory]
    [InlineData("retry", true, null, null)]
    [InlineData("retry", true, "not-a-url", "REQUESTS entry 'not-a-url' is not a valid absolute URL.")]
    [InlineData("transfer", false, null, "REQUESTS must contain at least one URL for testcase dispatch.")]
    [InlineData("post-handshake-stream", false, "http://localhost:443/dispatch", "REQUESTS entry 'http://localhost:443/dispatch' must use https for testcase dispatch.")]
    public void RunnerDispatchRequestUriContractCoversClientRetryTransferAndPostHandshakeStream(
        string testcase,
        bool allowEmptyRequests,
        string? requests,
        string? expectedErrorMessage)
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            CreateEnvironment("client", testcase, requests),
            out InteropHarnessEnvironment? environment,
            out string? creationError));
        Assert.NotNull(environment);
        Assert.Null(creationError);

        bool success = InteropHarnessRunner.TryGetDispatchRequestUri(
            environment!,
            out Uri? requestUri,
            out string? errorMessage,
            allowEmptyRequests);

        Assert.Equal(expectedErrorMessage is null, success);
        Assert.Null(requestUri);
        Assert.Equal(expectedErrorMessage, errorMessage);
    }

    [Theory]
    [InlineData("handshake", TlsMaterialScenario.MissingCertificate)]
    [InlineData("retry", TlsMaterialScenario.MissingPrivateKey)]
    [InlineData("post-handshake-stream", TlsMaterialScenario.InvalidPem)]
    public void ServerDispatchReportsTlsMaterialFailuresBeforeBootstrap(string testcase, TlsMaterialScenario scenario)
    {
        IDictionary environment = CreateEnvironment("server", testcase);
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessRunnerTests));

        string certificatePath;
        string privateKeyPath;
        string? expectedErrorMessage;

        switch (scenario)
        {
            case TlsMaterialScenario.MissingCertificate:
                certificatePath = Path.Combine(fixture.RootDirectory, $"missing-cert-{Guid.NewGuid():N}.pem");
                privateKeyPath = fixture.CreateFile("priv.key", "unused");
                expectedErrorMessage = $"TLS certificate not found at '{certificatePath}'.{Environment.NewLine}";
                break;

            case TlsMaterialScenario.MissingPrivateKey:
                certificatePath = fixture.CreateFile("cert.pem", "unused");
                privateKeyPath = Path.Combine(fixture.RootDirectory, $"missing-key-{Guid.NewGuid():N}.pem");
                expectedErrorMessage = $"TLS private key not found at '{privateKeyPath}'.{Environment.NewLine}";
                break;

            case TlsMaterialScenario.InvalidPem:
                (certificatePath, privateKeyPath) = InteropHarnessTestSupport.CreateTlsMaterialFixture(fixture);
                expectedErrorMessage = null;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(scenario), scenario, "Unsupported TLS material scenario.");
        }

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr, certificatePath, privateKeyPath);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());

        string stderrText = stderr.ToString();
        if (expectedErrorMessage is null)
        {
            Assert.StartsWith("Unable to create TLS server certificate:", stderrText, StringComparison.Ordinal);
            Assert.EndsWith(Environment.NewLine, stderrText, StringComparison.Ordinal);
        }
        else
        {
            Assert.Equal(expectedErrorMessage, stderrText);
        }
    }

    [Theory]
    [InlineData(false, "REQUESTS must contain at least one URL for testcase dispatch.")]
    [InlineData(true, null)]
    public void RequestValidationForwardingHonorsTheAllowEmptyRequestsFlag(bool allowEmptyRequests, string? expectedErrorMessage)
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            CreateEnvironment("server", "handshake"),
            out InteropHarnessEnvironment? environment,
            out string? creationError));

        Assert.NotNull(environment);
        Assert.Null(creationError);

        bool success = InteropHarnessRunner.TryGetDispatchRequestUri(
            environment!,
            out Uri? requestUri,
            out string? errorMessage,
            allowEmptyRequests);

        Assert.Equal(allowEmptyRequests, success);
        Assert.Null(requestUri);
        Assert.Equal(expectedErrorMessage, errorMessage);
    }

    [Fact]
    public void InvalidEnvironmentDefinitionsAreReportedWithoutDispatching()
    {
        IDictionary environment = CreateEnvironment(null, "handshake");

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());
        Assert.Equal("ROLE must be set to client or server." + Environment.NewLine, stderr.ToString());
    }

    private static IDictionary CreateEnvironment(string? role, string testcase, string? requests = null)
    {
        Hashtable environment = new(StringComparer.OrdinalIgnoreCase);

        if (role is not null)
        {
            environment["ROLE"] = role;
        }

        environment["TESTCASE"] = testcase;

        if (requests is not null)
        {
            environment["REQUESTS"] = requests;
        }

        return environment;
    }

    public enum TlsMaterialScenario
    {
        MissingCertificate,
        MissingPrivateKey,
        InvalidPem,
    }
}
