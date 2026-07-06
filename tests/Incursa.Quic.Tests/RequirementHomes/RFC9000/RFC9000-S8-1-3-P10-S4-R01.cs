// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-3-P10-S4-R01">If address-validation token validation succeeds, the server SHOULD allow the handshake to proceed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-3-P10-S4-R01")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_8135
{
    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidNewToken_AllowsTheServerHandshakeToProceedWithoutRetry()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
        byte[] token = scenario.IssueNewTokenForClient();

        scenario.SendInitialWithToken(token);

        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.False(scenario.ListenerHost.RetryBootstrapIssued);
        Assert.True(scenario.CallbackEntered.IsCompleted);
    }

    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S4-R01")]
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

    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task InvalidRetryToken_DoesNotAllowTheServerHandshakeToProceed()
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
        Assert.False(scenario.CallbackEntered.IsCompleted);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.TokenMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [Requirement("RFC9000-S8-1-3-P10-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_ValidNewTokenVariantsAllowTheServerHandshakeToProceedWithoutRetry()
    {
        foreach (TimeSpan validTokenAge in new[] { TimeSpan.Zero, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(4) })
        {
            QuicAddressValidationTokenProtector protector = CreateProtector();
            await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
                await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
            byte[] token = scenario.IssueNewTokenForClient(DateTimeOffset.UtcNow.Subtract(validTokenAge));

            scenario.SendInitialWithToken(token);

            await scenario.WaitForCallbackAsync();
            Assert.True(scenario.ListenerHost.NewTokenValidationAttempted);
            Assert.True(scenario.ListenerHost.NewTokenValidationSucceeded);
            Assert.False(scenario.ListenerHost.RetryBootstrapIssued);
            Assert.True(scenario.CallbackEntered.IsCompleted);
            Assert.Equal(0, scenario.ListenerHost.NewTokenValidationFailureCode);
        }
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
            secret[index] = unchecked((byte)(0xA0 + index));
        }

        return secret;
    }
}
