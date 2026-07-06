// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S17P4_SpinBit_DeferredFuzzClosure
{
    [Fact]
    [Requirement("RFC9000-S17-4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DisabledSpinBitFuzz_ClearsSpinBitAcrossRepresentativeConnections()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        foreach ((byte[] DestinationConnectionId, byte[] SourceConnectionId) in CreateConnectionIdPairs())
        {
            QuicHandshakeFlowCoordinator coordinator = new(DestinationConnectionId, SourceConnectionId);

            AssertOpenedSpinBit(
                coordinator,
                material,
                payload,
                expectedSpinBit: false,
                expectedDestinationConnectionIdLength: DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("RFC9000-S17-4-P4-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RandomizedSpinBitSelectionFuzz_DisablesAtLeastOneInEverySixteenConnectionIds()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();
        int disabledCount = 0;

        for (int connectionIndex = 0; connectionIndex < 16; connectionIndex++)
        {
            byte[] destinationConnectionId =
            [
                (byte)(0x10 + connectionIndex),
                (byte)(0x30 + connectionIndex),
            ];
            byte[] sourceConnectionId =
            [
                (byte)(0x50 + connectionIndex),
            ];

            QuicHandshakeFlowCoordinator coordinator = new(
                destinationConnectionId,
                sourceConnectionId,
                enableRandomizedSpinBitSelection: true);

            bool spinBit = ReadOpenedSpinBit(coordinator, material, payload, destinationConnectionId.Length);
            if (!spinBit)
            {
                disabledCount++;
            }
        }

        Assert.True(disabledCount >= 1);
    }

    [Fact]
    [Requirement("RFC9000-S17-4-P5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DisabledSpinBitOutputFuzz_UsesImplementationChosenClearedValue()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        foreach (bool requestedSpinBit in new[] { false, true })
        {
            foreach ((byte[] DestinationConnectionId, byte[] SourceConnectionId) in CreateConnectionIdPairs())
            {
                QuicHandshakeFlowCoordinator coordinator = new(DestinationConnectionId, SourceConnectionId);

                Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                    payload,
                    material,
                    keyPhase: false,
                    requestedSpinBit,
                    out _,
                    out byte[] protectedPacket));
                Assert.False(OpenSpinBit(coordinator, material, protectedPacket, DestinationConnectionId.Length, payload));
            }
        }
    }

    [Fact]
    [Requirement("RFC9000-S17-4-P5-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DisabledSpinBitInputFuzz_IgnoresIncomingSpinValuesAcrossConnections()
    {
        QuicTlsPacketProtectionMaterial material = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt);
        byte[] payload = QuicS12P3TestSupport.CreatePingPayload();

        foreach (bool incomingSpinBit in new[] { false, true })
        {
            foreach ((byte[] DestinationConnectionId, byte[] SourceConnectionId) in CreateConnectionIdPairs())
            {
                QuicHandshakeFlowCoordinator sender = new(
                    DestinationConnectionId,
                    SourceConnectionId,
                    enableRandomizedSpinBitSelection: true);
                Assert.True(sender.TryBuildProtectedApplicationDataPacket(
                    payload,
                    material,
                    keyPhase: false,
                    incomingSpinBit,
                    out _,
                    out byte[] incomingProtectedPacket));

                QuicHandshakeFlowCoordinator receiver = new(DestinationConnectionId, SourceConnectionId);
                Assert.Equal(
                    incomingSpinBit && !ShouldDisableSpinBit(DestinationConnectionId),
                    OpenSpinBit(receiver, material, incomingProtectedPacket, DestinationConnectionId.Length, payload));

                AssertOpenedSpinBit(
                    receiver,
                    material,
                    payload,
                    expectedSpinBit: false,
                    expectedDestinationConnectionIdLength: DestinationConnectionId.Length);
            }
        }
    }

    private static bool ReadOpenedSpinBit(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> payload,
        int expectedDestinationConnectionIdLength)
    {
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            material,
            out byte[] protectedPacket));

        return OpenSpinBit(coordinator, material, protectedPacket, expectedDestinationConnectionIdLength, payload);
    }

    private static void AssertOpenedSpinBit(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> payload,
        bool expectedSpinBit,
        int expectedDestinationConnectionIdLength)
    {
        bool spinBit = ReadOpenedSpinBit(
            coordinator,
            material,
            payload,
            expectedDestinationConnectionIdLength);
        Assert.Equal(expectedSpinBit, spinBit);
    }

    private static bool OpenSpinBit(
        QuicHandshakeFlowCoordinator coordinator,
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> protectedPacket,
        int expectedDestinationConnectionIdLength,
        ReadOnlySpan<byte> expectedPayload)
    {
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal(1 + expectedDestinationConnectionIdLength + 4, payloadOffset);
        Assert.True(payloadLength >= expectedPayload.Length);
        Assert.True(openedPacket.AsSpan(payloadOffset, expectedPayload.Length).SequenceEqual(expectedPayload));
        return header.SpinBit;
    }

    private static (byte[] DestinationConnectionId, byte[] SourceConnectionId)[] CreateConnectionIdPairs()
    {
        return
        [
            ([], []),
            ([0x10, 0x30], [0x50]),
            ([0x11, 0x31], [0x51]),
            ([0x1F, 0x3F, 0x5F, 0x7F], [0x71, 0x72]),
        ];
    }

    private static bool ShouldDisableSpinBit(ReadOnlySpan<byte> connectionId)
    {
        return connectionId.IsEmpty || (connectionId[0] & 0x0F) == 0;
    }
}
