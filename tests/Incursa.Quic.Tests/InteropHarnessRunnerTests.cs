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
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessRunnerTests));
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        IDictionary environment = CreateEnvironment(role, "multipath", qlogDir: qlogDirectory);

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(127, exitCode);
        Assert.Equal(
            $"interop harness: role={role}, testcase=multipath, requestCount=0 is currently unsupported.{Environment.NewLine}",
            stdout.ToString());
        Assert.Equal(string.Empty, stderr.ToString());
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }

    [Theory]
    [InlineData("handshake", false, "not-a-url", "REQUESTS entry 'not-a-url' is not a valid absolute URL.")]
    [InlineData("retry", true, "not-a-url", "REQUESTS entry 'not-a-url' is not a valid absolute URL.")]
    [InlineData("post-handshake-stream", true, "http://localhost:443/dispatch", "REQUESTS entry 'http://localhost:443/dispatch' must use https for testcase dispatch.")]
    public void RunnerDispatchRequestUriContractCoversClientHandshakeRetryAndPostHandshakeStream(
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
    [InlineData("server", "handshake", true, null)]
    [InlineData("server", "post-handshake-stream", true, null)]
    [InlineData("server", "retry", true, null)]
    [InlineData("server", "transfer", true, null)]
    [InlineData("client", "handshake", false, "REQUESTS must contain at least one URL for testcase dispatch.")]
    [InlineData("client", "post-handshake-stream", false, "REQUESTS must contain at least one URL for testcase dispatch.")]
    [InlineData("client", "retry", false, "REQUESTS must contain at least one URL for testcase dispatch.")]
    [InlineData("client", "transfer", false, "REQUESTS must contain at least one URL for testcase dispatch.")]
    public void SupportedServerPathsAllowEmptyRequestsWhileClientPathsRejectThem(
        string role,
        string testcase,
        bool allowEmptyRequests,
        string? expectedErrorMessage)
    {
        Assert.True(InteropHarnessEnvironment.TryCreate(
            CreateEnvironment(role, testcase),
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
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessRunnerTests));
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        IDictionary environment = CreateEnvironment("server", testcase, qlogDir: qlogDirectory);

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
        Assert.DoesNotContain("qlog capture enabled", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));

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
    [InlineData("transfer", "https://localhost:443/", "REQUESTS entry 'https://localhost/' must include a non-root path for transfer dispatch.")]
    [InlineData("transfer", "https://localhost:443/one https://localhost:444/two", "REQUESTS entry 'https://localhost:444/two' must target the same host and port as the first request URL.")]
    public void ClientTransferDispatchFailuresDoNotAdvertiseSuccessOrQlogCapture(
        string testcase,
        string requests,
        string expectedErrorMessage)
    {
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessRunnerTests));
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        IDictionary environment = CreateEnvironment("client", testcase, requests, qlogDirectory);

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());
        Assert.DoesNotContain("qlog capture enabled", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(expectedErrorMessage + Environment.NewLine, stderr.ToString());
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
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

    [Fact]
    public void ServerRequestLoopTreatsRemoteApplicationCloseNoErrorAsCompletionOnlyAfterAnEmptyRequestServerHasServedARequest()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-132744806-server-nginx
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260422-134139006-server-nginx
        //   the live server-role handshake completed the response and then the peer sent
        //   APPLICATION_CLOSE 0x0. The helper should only treat that as completion for the
        //   empty-REQUESTS server lane after at least one request was already served.
        QuicException cleanRemoteClose = new(QuicError.ConnectionAborted, 0, "The connection terminated.");

        Assert.True(InteropHarnessRunner.ShouldTreatServerCloseAsRequestLoopCompletion(
            cleanRemoteClose,
            expectedRequestCount: 0,
            servedRequestCount: 1));
        Assert.False(InteropHarnessRunner.ShouldTreatServerCloseAsRequestLoopCompletion(
            cleanRemoteClose,
            expectedRequestCount: 1,
            servedRequestCount: 1));
        Assert.False(InteropHarnessRunner.ShouldTreatServerCloseAsRequestLoopCompletion(
            cleanRemoteClose,
            expectedRequestCount: 0,
            servedRequestCount: 0));
    }

    [Fact]
    public void ServerRequestLoopDoesNotTreatOtherTerminalOutcomesAsCompletion()
    {
        QuicException nonZeroApplicationClose = new(QuicError.ConnectionAborted, 7, "The connection terminated.");
        QuicException idleTimeout = new(QuicError.ConnectionIdle, null, "The connection idled.");

        Assert.False(InteropHarnessRunner.ShouldTreatServerCloseAsRequestLoopCompletion(
            nonZeroApplicationClose,
            expectedRequestCount: 0,
            servedRequestCount: 1));
        Assert.False(InteropHarnessRunner.ShouldTreatServerCloseAsRequestLoopCompletion(
            idleTimeout,
            expectedRequestCount: 0,
            servedRequestCount: 1));
    }

    private static IDictionary CreateEnvironment(
        string? role,
        string testcase,
        string? requests = null,
        string? qlogDir = null)
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

        if (qlogDir is not null)
        {
            environment["QLOGDIR"] = qlogDir;
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
