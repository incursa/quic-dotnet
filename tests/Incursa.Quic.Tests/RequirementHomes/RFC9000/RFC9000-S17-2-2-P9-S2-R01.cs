// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S17-2-2-P9-S2-R01">A server MAY send multiple Initial packets</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S17-2-2-P9-S2-R01")]
public sealed class RFC9000_S17_2_2_P9_S2_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S17-2-2-P9-S2-R01")]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_RejectsServerInitialsWithoutASourceConnectionId()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = new(
            QuicS17P2P2TestSupport.InitialDestinationConnectionId);
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));

        Assert.False(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            QuicS12P3TestSupport.CreateSequentialBytes(0xA0, 20),
            cryptoPayloadOffset: 0,
            serverProtection,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S17-2-2-P9-S2-R01">A server MAY send multiple Initial packets</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S17-2-2-P9-S2-R01")]
    public void TryBuildProtectedInitialPacketForHandshakeDestination_AllowsTheServerToSendMultipleInitialPackets()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateServerCoordinator();
        Assert.True(coordinator.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));

        byte[] firstCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x70, 20);
        byte[] secondCryptoPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x90, 24);

        Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            firstCryptoPayload,
            cryptoPayloadOffset: 0,
            serverProtection,
            out ulong firstPacketNumber,
            out byte[] firstProtectedPacket));
        Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
            secondCryptoPayload,
            cryptoPayloadOffset: (ulong)firstCryptoPayload.Length,
            serverProtection,
            out ulong secondPacketNumber,
            out byte[] secondProtectedPacket));
        Assert.Equal(0UL, firstPacketNumber);
        Assert.Equal(1UL, secondPacketNumber);

        Assert.True(coordinator.TryOpenInitialPacket(
            firstProtectedPacket,
            clientProtection,
            out byte[] firstOpenedPacket,
            out int firstPayloadOffset,
            out int firstPayloadLength));
        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            firstOpenedPacket,
            firstPayloadOffset,
            firstPayloadLength,
            firstCryptoPayload,
            expectedCryptoOffset: 0);

        Assert.True(coordinator.TryOpenInitialPacket(
            secondProtectedPacket,
            clientProtection,
            out byte[] secondOpenedPacket,
            out int secondPayloadOffset,
            out int secondPayloadLength));
        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            secondOpenedPacket,
            secondPayloadOffset,
            secondPayloadLength,
            secondCryptoPayload,
            expectedCryptoOffset: (ulong)firstCryptoPayload.Length);
    }
}
