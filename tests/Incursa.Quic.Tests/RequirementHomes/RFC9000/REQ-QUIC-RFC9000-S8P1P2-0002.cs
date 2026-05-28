// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1P2-0002">Instead, the server SHOULD immediately close (Section 10.2) the connection with an INVALID_TOKEN error.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1P2-0002")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_S8P1P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P2-0002")]
    [Requirement("REQ-QUIC-RFC9000-S8P1P2-0004")]
    public async Task ListenerHostSendsInvalidTokenCloseForATamperedRetryReplayToken()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        byte[] tamperedRetryToken = retryMetadata.RetryToken.ToArray();
        tamperedRetryToken[^1] ^= 0x01;
        scenario.SendRetryReplay(tamperedRetryToken);

        byte[] response = await scenario.ReceiveDatagramAsync();
        Assert.True(QuicS5P2P2ServerPreAcceptanceTestSupport.TryOpenInitialConnectionCloseFrame(
            response,
            retryMetadata.RetrySourceConnectionId,
            out ulong errorCode,
            out ulong triggeringFrameType));
        Assert.Equal((ulong)QuicTransportErrorCode.InvalidToken, errorCode);
        Assert.Equal(0UL, triggeringFrameType);
        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(tamperedRetryToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
    }
}
