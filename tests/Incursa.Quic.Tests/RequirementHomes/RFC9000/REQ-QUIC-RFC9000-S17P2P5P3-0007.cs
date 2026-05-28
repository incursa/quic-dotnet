// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0007")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0007")]
    public void PostRetryZeroRttPacketsProtectConfidentialApplicationPayloadBytes()
    {
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P5P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P5P2TestSupport.RetrySourceConnectionId));
        QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt);
        byte[] confidentialApplicationFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            streamData: QuicS12P3TestSupport.CreateSequentialBytes(0xA0, 32),
            offset: 0);

        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            confidentialApplicationFrame,
            zeroRttMaterial,
            out byte[] protectedZeroRttPacket));

        Assert.True(QuicS17P2P3TestSupport.IsZeroRttPacket(protectedZeroRttPacket));
        Assert.False(QuicS17P2P5P2TestSupport.ContainsSubsequence(
            protectedZeroRttPacket,
            confidentialApplicationFrame));
    }
}
