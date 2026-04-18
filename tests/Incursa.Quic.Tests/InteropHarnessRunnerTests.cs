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
    [InlineData(null, "ROLE must be set to client or server.")]
    [InlineData("bogus", "Unsupported ROLE value 'bogus'. Expected client or server.")]
    public void InvalidEnvironmentDefinitionsAreReportedWithoutDispatching(string? role, string expectedErrorMessage)
    {
        IDictionary environment = CreateEnvironment(role, "handshake");

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());
        Assert.Equal(expectedErrorMessage + Environment.NewLine, stderr.ToString());
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
    public void ServerHandshakeReportsTlsMaterialErrorsBeforeAnySocketOrPeerWork()
    {
        IDictionary environment = CreateEnvironment("server", "handshake");
        string certificatePath = Path.Combine(Path.GetTempPath(), $"missing-cert-{Guid.NewGuid():N}.pem");
        string privateKeyPath = Path.Combine(Path.GetTempPath(), $"missing-key-{Guid.NewGuid():N}.pem");

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr, certificatePath, privateKeyPath);

        Assert.Equal(1, exitCode);
        Assert.Equal(string.Empty, stdout.ToString());
        Assert.Equal($"TLS certificate not found at '{certificatePath}'.{Environment.NewLine}", stderr.ToString());
    }

    private static IDictionary CreateEnvironment(string? role, string testcase)
    {
        Hashtable environment = new(StringComparer.OrdinalIgnoreCase);

        if (role is not null)
        {
            environment["ROLE"] = role;
        }

        environment["TESTCASE"] = testcase;
        return environment;
    }
}
