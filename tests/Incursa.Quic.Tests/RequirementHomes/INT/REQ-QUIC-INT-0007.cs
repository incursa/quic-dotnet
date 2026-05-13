namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0007")]
public sealed class REQ_QUIC_INT_0007
{
    [Theory]
    [InlineData("multipath")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnsupportedInteropTestCasesReturn127WithoutPretendingTlsSupport(string testcase)
    {
        using StringWriter stdout = new();

        int exitCode = InteropHarnessRunner.Run(
            InteropHarnessTestSupport.CreateEnvironment("server", testcase),
            stdout,
            TextWriter.Null);

        Assert.Equal(127, exitCode);
        Assert.Contains($"testcase={testcase}", stdout.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZerorttDoesNotExecuteKeylogExportForTheUnsupportedClientRole()
    {
        using TempDirectoryFixture fixture = new("interop-zerortt-unsupported");
        string keyLogPath = Path.Combine(fixture.RootDirectory, "sslkeys.log");
        using StringWriter stdout = new();

        int exitCode = InteropHarnessRunner.Run(
            InteropHarnessTestSupport.CreateEnvironment(
                "client",
                "zerortt",
                sslKeyLogFile: keyLogPath),
            stdout,
            TextWriter.Null);

        string output = stdout.ToString();

        Assert.Equal(127, exitCode);
        Assert.Contains("unsupported testcase does not execute keylog export", output, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("testcase=zerortt", output, StringComparison.OrdinalIgnoreCase);
        Assert.False(File.Exists(keyLogPath));
    }
}
