namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0009")]
public sealed class REQ_QUIC_INT_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnsupportedDispatchDoesNotFabricateQlogOrKeylogArtifacts()
    {
        using TempDirectoryFixture fixture = new("incursa-quic-interop-tests");
        string qlogDirectory = Path.Combine(fixture.RootDirectory, "qlog");
        string sslKeyLogFile = Path.Combine(fixture.RootDirectory, "keys.log");

        int exitCode = InteropHarnessRunner.Run(
            InteropHarnessTestSupport.CreateEnvironment(
                role: "client",
                testcase: "multipath",
                qlogDir: qlogDirectory,
                sslKeyLogFile: sslKeyLogFile),
            TextWriter.Null,
            TextWriter.Null);

        Assert.Equal(127, exitCode);
        Assert.False(Directory.Exists(qlogDirectory));
        Assert.False(File.Exists(sslKeyLogFile));
    }
}
