namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0002">It MUST be used by a server that wishes to perform a retry; see Section 8.1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0002")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0002")]
    public async Task RetryValidationScenario_IssuesRetryPacketWhenTheServerChoosesRetry()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();

        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        Assert.True(scenario.ListenerHost.RetryBootstrapIssued);
        Assert.NotEmpty(retryMetadata.RetrySourceConnectionId);
        Assert.NotEmpty(retryMetadata.RetryToken);
    }
}
