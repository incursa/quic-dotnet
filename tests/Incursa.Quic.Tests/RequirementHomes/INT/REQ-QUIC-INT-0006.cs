namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0006")]
public sealed class REQ_QUIC_INT_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HarnessParsesRoleTestCaseRequestListAndFixedMountPaths()
    {
        IDictionary environment = InteropHarnessTestSupport.CreateEnvironment(
            role: "client",
            testcase: "handshake",
            requests: "alpha beta",
            qlogDir: "/tmp/qlog",
            sslKeyLogFile: "/tmp/keys.log");

        Assert.True(InteropHarnessEnvironment.TryCreate(environment, out InteropHarnessEnvironment? settings, out string? errorMessage));
        Assert.Null(errorMessage);
        Assert.NotNull(settings);

        Assert.Equal(InteropHarnessRole.Client, settings!.Role);
        Assert.Equal("handshake", settings.TestCase);
        Assert.Equal(new[] { "alpha", "beta" }, settings.Requests);
        Assert.Equal("/tmp/qlog", settings.QlogDirectory);
        Assert.Equal("/tmp/keys.log", settings.SslKeyLogFile);
        Assert.Equal("/www", InteropHarnessEnvironment.WwwDirectory);
        Assert.Equal("/downloads", InteropHarnessEnvironment.DownloadsDirectory);
        Assert.Equal("/certs/cert.pem", InteropHarnessEnvironment.CertificatePath);
        Assert.Equal("/certs/priv.key", InteropHarnessEnvironment.PrivateKeyPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidRoleValuesAreRejectedBeforeDispatch()
    {
        IDictionary environment = InteropHarnessTestSupport.CreateEnvironment("bogus", "handshake");

        Assert.False(InteropHarnessEnvironment.TryCreate(environment, out _, out string? errorMessage));
        Assert.NotNull(errorMessage);
        Assert.Contains("ROLE", errorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingTestCaseIsRejectedBeforeDispatch()
    {
        Hashtable environment = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ROLE"] = "client",
        };

        Assert.False(InteropHarnessEnvironment.TryCreate(environment, out _, out string? errorMessage));
        Assert.NotNull(errorMessage);
        Assert.Contains("TESTCASE", errorMessage, StringComparison.OrdinalIgnoreCase);
    }
}
