// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0007">The cryptographic handshake ensures that only the communicating endpoints receive the corresponding keys for Handshake, 0-RTT, and 1-RTT packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0007")]
public sealed class REQ_QUIC_RFC9000_S12P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakePacketProtectionRoundTripsWithMatchingTlsMaterial()
    {
        QuicTlsPacketProtectionMaterial material = QuicS13AckPiggybackTestSupport.CreateHandshakeMaterial();

        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection senderProtection));
        Assert.True(QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection receiverProtection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId:
            [
                0x10, 0x11, 0x12, 0x13,
            ],
            sourceConnectionId:
            [
                0x20, 0x21,
            ],
            packetNumber:
            [
                0x01, 0x02,
            ],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x40, 24));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);

        byte[] recoveredPacket = new byte[plaintextPacket.Length];
        Assert.True(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            recoveredPacket,
            out int recoveredBytesWritten));

        Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
        Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HandshakePacketProtectionRejectsPacketsProtectedWithDifferentTlsMaterial()
    {
        QuicTlsPacketProtectionMaterial matchingMaterial = QuicS13AckPiggybackTestSupport.CreateHandshakeMaterial();

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            QuicS12P3TestSupport.CreateSequentialBytes(0x71, 16),
            QuicS12P3TestSupport.CreateSequentialBytes(0x81, 12),
            QuicS12P3TestSupport.CreateSequentialBytes(0x91, 16),
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial differentMaterial));

        Assert.True(QuicHandshakePacketProtection.TryCreate(matchingMaterial, out QuicHandshakePacketProtection senderProtection));
        Assert.True(QuicHandshakePacketProtection.TryCreate(differentMaterial, out QuicHandshakePacketProtection receiverProtection));

        byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
            destinationConnectionId:
            [
                0x10, 0x11, 0x12, 0x13,
            ],
            sourceConnectionId:
            [
                0x20, 0x21,
            ],
            packetNumber:
            [
                0x01,
            ],
            plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes(0x40, 24));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));

        Assert.False(receiverProtection.TryOpen(
            protectedPacket.AsSpan(0, protectedBytesWritten),
            new byte[plaintextPacket.Length],
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientRuntimeRevealsZeroRttAndOneRttKeysOnlyAtTheirHandshakeBoundaries()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        Assert.False(clientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.False(clientRuntime.TlsState.OneRttKeysAvailable);
        Assert.False(clientRuntime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));

        QuicConnectionTransitionResult bootstrapResult = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks: nowTicks);

        Assert.True(bootstrapResult.StateChanged);
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _));
        Assert.False(clientRuntime.TlsState.OneRttKeysAvailable);

        using QuicConnectionRuntime finishedClientRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        Assert.True(finishedClientRuntime.TlsState.OneRttKeysAvailable);
    }
}
