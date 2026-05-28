// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0006">To protect against such attacks, servers MUST ensure that replay of tokens is prevented or limited.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0008">Tokens that are provided in NEW_TOKEN frames (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0009">Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include additional information about clients to further narrow applicability or reuse.</workbench-requirement>
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P4-0012">To protect against replay attacks, servers MUST ensure that replay of tokens is prevented or limited.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0006")]
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0008")]
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0009")]
[Requirement("REQ-QUIC-RFC9000-S8P1P4-0012")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S8P1P4_0012
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0006")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0008")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0009")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P4-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Negative")]
    public async Task NewTokenReplay_IsRejectedAfterTheFirstSuccessfulUse()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
        byte[] token = scenario.IssueNewTokenForClient();

        scenario.SendInitialWithToken(token);

        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.Equal(1, scenario.CallbackCount);
        Assert.False(scenario.ListenerHost.RetryBootstrapIssued);

        byte[] replayDestinationConnectionId =
        [
            0x91, 0x92, 0x93, 0x94,
            0x95, 0x96, 0x97, 0x98,
        ];
        QuicRetryBootstrapMetadata retry =
            await scenario.SendInitialWithTokenAndReceiveRetryAsync(token, replayDestinationConnectionId);

        await scenario.WaitForNoAdditionalCallbacksAsync(1);
        Assert.NotEmpty(retry.RetryToken);
        Assert.True(scenario.ListenerHost.NewTokenValidationAttempted);
        Assert.False(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.Equal(
            (int)QuicAddressValidationTokenValidationResult.Replayed,
            scenario.ListenerHost.NewTokenValidationFailureCode);
        Assert.True(scenario.ListenerHost.RetryBootstrapIssued);
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
            secret[index] = unchecked((byte)(0xB0 + index));
        }

        return secret;
    }
}
