// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P2-S5-R01">Servers MAY discard Initial packets that do not carry the expected address-validation token.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P2-S5-R01")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_0393
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RetryReplayCandidateWithExpectedToken_IsAdmittedInsteadOfDiscarded()
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

    [Fact]
    [Requirement("RFC9000-S8-1-3-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RetryReplayCandidateWithWrongExpectedToken_IsDiscardedWithoutAdmission()
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
    [Requirement("RFC9000-S8-1-3-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RetryReplayCandidateWithoutExpectedToken_IsDiscardedWithoutAdmission()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        _ = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(ReadOnlySpan<byte>.Empty);

        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayAdmitted);
        Assert.Equal(string.Empty, scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.TokenMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }
}
