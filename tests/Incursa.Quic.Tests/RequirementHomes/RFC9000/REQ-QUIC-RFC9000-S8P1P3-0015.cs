namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0015">If an address-validation token is invalid, the server SHOULD proceed as if the client address is not validated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0015")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0015
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task InvalidRetryToken_DoesNotAdmitTheClientAsAddressValidated()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        byte[] wrongToken = retryMetadata.RetryToken.ToArray();
        wrongToken[^1] ^= 0x01;
        scenario.SendRetryReplay(wrongToken);

        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayAdmitted);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.TokenMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ValidRetryToken_DoesNotUseTheInvalidTokenDisposition()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForCallbackAsync();
        await scenario.WaitForReplayAdmittedAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayAdmitted);
        Assert.Equal(0, scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }
}
