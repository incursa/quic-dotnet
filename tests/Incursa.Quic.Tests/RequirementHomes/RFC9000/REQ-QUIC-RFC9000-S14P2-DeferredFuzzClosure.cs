// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S14P2_DeferredFuzzClosure
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    private static readonly byte[] ApplicationDestinationConnectionId =
    [
        0x31, 0x32, 0x33, 0x34,
    ];

    private static readonly byte[] ApplicationSourceConnectionId =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtectedUdpPayloadsContainQuicPacketHeadersAndProtectedPayloadBytes()
    {
        foreach (int payloadLength in new[] { 1, 3, 17, 63 })
        {
            byte[] cryptoPayload = Enumerable.Range(0, payloadLength).Select(static index => (byte)(0x20 + index)).ToArray();
            byte[] applicationPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, payloadLength);

            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Client,
                InitialDestinationConnectionId,
                out QuicInitialPacketProtection initialProtection));
            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                InitialDestinationConnectionId,
                out QuicInitialPacketProtection initialOpenProtection));
            Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.OneRtt,
                out QuicTlsPacketProtectionMaterial applicationMaterial));

            QuicHandshakeFlowCoordinator initialCoordinator =
                new(InitialDestinationConnectionId, InitialSourceConnectionId);
            Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                initialProtection,
                out byte[] protectedInitialPacket));
            Assert.True(QuicPacketParser.TryParseLongHeader(protectedInitialPacket, out QuicLongHeaderPacket initialHeader));
            Assert.Equal((byte)QuicLongPacketTypeBits.Initial, initialHeader.LongPacketTypeBits);
            Assert.True(initialCoordinator.TryOpenInitialPacket(
                protectedInitialPacket,
                initialOpenProtection,
                out byte[] openedInitialPacket,
                out int initialPayloadOffset,
                out int initialPayloadLength));
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                openedInitialPacket.AsSpan(initialPayloadOffset, initialPayloadLength),
                out QuicCryptoFrame parsedCryptoFrame,
                out int cryptoBytesConsumed));
            Assert.True(parsedCryptoFrame.CryptoData.SequenceEqual(cryptoPayload));
            ReadOnlySpan<byte> remainingInitialPayload =
                openedInitialPacket.AsSpan(initialPayloadOffset + cryptoBytesConsumed, initialPayloadLength - cryptoBytesConsumed);
            Assert.True(remainingInitialPayload.ToArray().All(static value => value == 0));

            QuicHandshakeFlowCoordinator applicationCoordinator =
                new(ApplicationDestinationConnectionId, ApplicationSourceConnectionId);
            Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                applicationMaterial,
                out byte[] protectedApplicationPacket));
            Assert.True(applicationCoordinator.TryOpenProtectedApplicationDataPacket(
                protectedApplicationPacket,
                applicationMaterial,
                out byte[] openedApplicationPacket,
                out int applicationPayloadOffset,
                out int applicationPayloadLength,
                out bool keyPhase));
            Assert.False(keyPhase);
            Assert.True(QuicPacketParser.TryParseShortHeader(openedApplicationPacket, out QuicShortHeaderPacket shortHeader));
            Assert.True(shortHeader.FixedBit);
            ReadOnlySpan<byte> openedApplicationPayload =
                openedApplicationPacket.AsSpan(applicationPayloadOffset, applicationPayloadLength);
            Assert.True(openedApplicationPayload[..applicationPayload.Length].SequenceEqual(applicationPayload));
            Assert.True(openedApplicationPayload[applicationPayload.Length..].ToArray().All(static value => value == 0));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MaximumDatagramSizeStateTracksTheLargestUdpPayloadSizeAllowedOnThePath()
    {
        ulong minimum = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        foreach (ulong maximumDatagramSize in new[] { minimum, minimum + 1, 1_350UL, 1_472UL })
        {
            QuicConnectionPathMaximumDatagramSizeState pathState =
                QuicConnectionPathMaximumDatagramSizeState.CreateInitial().WithMaximumDatagramSize(maximumDatagramSize);
            QuicCongestionControlState congestion = new();

            congestion.UpdateMaxDatagramSize(maximumDatagramSize, resetToInitialWindow: false);

            Assert.Equal(maximumDatagramSize, pathState.MaximumDatagramSizeBytes);
            Assert.Equal(maximumDatagramSize, congestion.MaxDatagramSizeBytes);
            Assert.True(pathState.CanSend(maximumDatagramSize));
            Assert.False(pathState.CanSend(maximumDatagramSize + 1));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PmtuProbeDatagramsAreAllowedOnlyWhenLargerThanTheCurrentMaximumDatagramSize()
    {
        foreach (ulong currentMaximumDatagramSize in new[] { 1_200UL, 1_280UL, 1_350UL, 1_500UL })
        {
            QuicConnectionPathMaximumDatagramSizeState state =
                QuicConnectionPathMaximumDatagramSizeState.CreateInitial().WithMaximumDatagramSize(currentMaximumDatagramSize);

            Assert.False(state.CanSend(currentMaximumDatagramSize - 1, isProbePacket: true));
            Assert.False(state.CanSend(currentMaximumDatagramSize, isProbePacket: true));
            Assert.True(state.CanSend(currentMaximumDatagramSize + 1, isProbePacket: true));
            Assert.True(state.CanSend(currentMaximumDatagramSize + 64, isProbePacket: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OrdinaryPacketsFitWithinTheCurrentMaximumDatagramSize()
    {
        ulong minimum = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        foreach (ulong currentMaximumDatagramSize in new[] { minimum, 1_248UL, 1_350UL, 1_472UL })
        {
            QuicConnectionPathMaximumDatagramSizeState state =
                QuicConnectionPathMaximumDatagramSizeState.CreateInitial().WithMaximumDatagramSize(currentMaximumDatagramSize);

            Assert.True(state.CanSend(1));
            Assert.True(state.CanSend(currentMaximumDatagramSize - 1));
            Assert.True(state.CanSend(currentMaximumDatagramSize));
            Assert.False(state.CanSend(currentMaximumDatagramSize + 1));
            Assert.False(state.CanSend(0));
        }
    }
}
