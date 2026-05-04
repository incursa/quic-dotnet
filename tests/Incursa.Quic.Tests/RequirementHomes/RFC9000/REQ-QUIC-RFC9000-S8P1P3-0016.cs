namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0016">If address-validation token validation succeeds, the server SHOULD allow the handshake to proceed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0016")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0016
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0016")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidRetryToken_AllowsTheServerHandshakeToProceed()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForCallbackAsync();
        await scenario.WaitForReplayAdmittedAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayAdmitted);
        Assert.True(scenario.CallbackEntered.IsCompleted);
    }
}
