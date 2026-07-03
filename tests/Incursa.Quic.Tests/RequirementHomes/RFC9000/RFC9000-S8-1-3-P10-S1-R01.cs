// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P10-S1-R01">A server that receives an Initial packet with an address validation token MUST attempt to validate the token unless address validation is already complete.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P10-S1-R01")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S8P1P3_0014
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task NewTokenInitialWithValidToken_IsValidatedBeforeAdmission()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
        byte[] token = scenario.IssueNewTokenForClient();

        scenario.SendInitialWithToken(token);

        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.NewTokenValidationAttempted);
        Assert.True(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.Equal(Convert.ToHexString(token), scenario.ListenerHost.NewTokenValidationTokenHex);
        Assert.Equal(0, scenario.ListenerHost.NewTokenValidationFailureCode);
        Assert.False(scenario.ListenerHost.RetryBootstrapIssued);
    }

    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task NewTokenInitialWithWrongAddressToken_IsValidatedAndRejected()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
        byte[] token = scenario.IssueNewTokenForAddress("203.0.113.200");

        _ = await scenario.SendInitialWithTokenAndReceiveRetryAsync(token);

        await scenario.WaitForNoCallbackAsync();
        Assert.True(scenario.ListenerHost.NewTokenValidationAttempted);
        Assert.False(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.Equal(
            (int)QuicAddressValidationTokenValidationResult.IntegrityFailure,
            scenario.ListenerHost.NewTokenValidationFailureCode);
        Assert.True(scenario.ListenerHost.RetryBootstrapIssued);
    }

    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S1-R01")]
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
    [Requirement("RFC9000-S8-1-3-P10-S1-R01")]
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
    [Requirement("RFC9000-S8-1-3-P10-S1-R01")]
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

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0x80 + index));
        }

        return secret;
    }
}
