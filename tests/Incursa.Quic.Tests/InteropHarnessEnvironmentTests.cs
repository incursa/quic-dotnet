using System.Collections;
using Incursa.Quic.InteropHarness;

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessEnvironmentTests
{
    [Theory]
    [InlineData("client", "Client")]
    [InlineData(" CLIENT ", "Client")]
    [InlineData("server", "Server")]
    [InlineData(" Server ", "Server")]
    public void TryParseRoleAcceptsClientAndServerIgnoringCaseAndOuterWhitespace(string input, string expectedRoleName)
    {
        Assert.True(InteropHarnessEnvironment.TryParseRole(input, out InteropHarnessRole role));
        Assert.Equal(expectedRoleName, role.ToString());
    }

    [Fact]
    public void TryCreateNormalizesTestCaseAndPassesThroughOptionalEnvironmentValues()
    {
        IDictionary environment = CreateEnvironment(
            role: " server ",
            testcase: "  HANDSHAKE  ",
            requests: "https://one\t\nhttps://two   https://three",
            qlogDir: "/tmp/qlog",
            sslKeyLogFile: "/tmp/keys.log");

        Assert.True(InteropHarnessEnvironment.TryCreate(environment, out InteropHarnessEnvironment? settings, out string? errorMessage));
        Assert.Null(errorMessage);
        Assert.NotNull(settings);

        Assert.Equal(InteropHarnessRole.Server, settings!.Role);
        Assert.Equal("handshake", settings.TestCase);
        Assert.Equal(new[] { "https://one", "https://two", "https://three" }, settings.Requests);
        Assert.Equal("/tmp/qlog", settings.QlogDirectory);
        Assert.Equal("/tmp/keys.log", settings.SslKeyLogFile);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   \t  \n ")]
    public void TryCreateTreatsMissingOrWhitespaceOnlyRequestsAsEmpty(string? requests)
    {
        IDictionary environment = CreateEnvironment(role: "client", testcase: "transfer", requests: requests);

        Assert.True(InteropHarnessEnvironment.TryCreate(environment, out InteropHarnessEnvironment? settings, out string? errorMessage));
        Assert.Null(errorMessage);
        Assert.NotNull(settings);
        Assert.Empty(settings!.Requests);
    }

    [Theory]
    [InlineData(null, "handshake", "ROLE must be set to client or server.")]
    [InlineData("", "handshake", "ROLE must be set to client or server.")]
    [InlineData("bogus", "handshake", "Unsupported ROLE value 'bogus'. Expected client or server.")]
    [InlineData("client", null, "TESTCASE must be set.")]
    [InlineData("client", "   ", "TESTCASE must be set.")]
    public void TryCreateRejectsInvalidEnvironmentInputs(string? role, string? testcase, string expectedErrorMessage)
    {
        IDictionary environment = CreateEnvironment(role: role, testcase: testcase);

        Assert.False(InteropHarnessEnvironment.TryCreate(environment, out _, out string? errorMessage));
        Assert.Equal(expectedErrorMessage, errorMessage);
    }

    private static IDictionary CreateEnvironment(
        string? role,
        string? testcase,
        string? requests = null,
        string? qlogDir = null,
        string? sslKeyLogFile = null)
    {
        Hashtable environment = new(StringComparer.OrdinalIgnoreCase);

        if (role is not null)
        {
            environment["ROLE"] = role;
        }

        if (testcase is not null)
        {
            environment["TESTCASE"] = testcase;
        }

        if (requests is not null)
        {
            environment["REQUESTS"] = requests;
        }

        if (qlogDir is not null)
        {
            environment["QLOGDIR"] = qlogDir;
        }

        if (sslKeyLogFile is not null)
        {
            environment["SSLKEYLOGFILE"] = sslKeyLogFile;
        }

        return environment;
    }
}
