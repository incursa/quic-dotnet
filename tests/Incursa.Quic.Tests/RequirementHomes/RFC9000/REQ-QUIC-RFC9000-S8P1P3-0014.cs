namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P3-0014">A server that receives an Initial packet with an address validation token MUST attempt to validate the token unless address validation is already complete.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P3-0014")]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0014
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RetryReplayCandidateWithValidToken_IsValidatedBeforeAdmission()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(0, scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RetryReplayCandidateWithWrongToken_IsValidatedAndRejected()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        byte[] wrongToken = retryMetadata.RetryToken.ToArray();
        wrongToken[^1] ^= 0x01;
        scenario.SendRetryReplay(wrongToken);

        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(wrongToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.TokenMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P3-0014")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RetryReplayCandidateWithEmptyToken_IsValidatedAndRejected()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        _ = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(ReadOnlySpan<byte>.Empty);

        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(string.Empty, scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.TokenMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }
}
