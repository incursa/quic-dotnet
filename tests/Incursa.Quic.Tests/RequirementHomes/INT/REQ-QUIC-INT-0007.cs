namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0007")]
public sealed class REQ_QUIC_INT_0007
{
    [Theory]
    [InlineData("transfer")]
    [InlineData("retry")]
    [InlineData("multipath")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnsupportedInteropTestCasesReturn127WithoutPretendingTlsSupport(string testcase)
    {
        int exitCode = InteropHarnessRunner.Run(
            InteropHarnessTestSupport.CreateEnvironment("server", testcase),
            TextWriter.Null,
            TextWriter.Null);

        Assert.Equal(127, exitCode);
    }
}
