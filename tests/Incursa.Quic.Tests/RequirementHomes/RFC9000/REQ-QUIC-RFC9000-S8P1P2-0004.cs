namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P2-0004">If a server receives a client Initial that contains an invalid Retry token but is otherwise valid, it SHOULD immediately close the connection with an INVALID_TOKEN error.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P2-0004")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S8P1P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P2-0002")]
    public async Task ListenerHostDoesNotCloseValidRetryReplayTokenWithInvalidTokenError()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForReplayAdmittedAsync();
        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(0, scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
    }
}
