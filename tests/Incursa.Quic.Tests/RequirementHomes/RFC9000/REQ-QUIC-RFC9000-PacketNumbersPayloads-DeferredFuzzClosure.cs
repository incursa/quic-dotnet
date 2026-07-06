// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_PacketNumbersPayloads_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0709")]
    [Requirement("REQ-QUIC-RFC9000-0710")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ApplicationPacketNumberBoundaryFuzz_DoesNotReusePacketNumbersAndStopsAtExhaustion()
    {
        foreach (ulong startingPacketNumber in new[]
        {
            0UL,
            1UL,
            (ulong)ushort.MaxValue - 1,
            (ulong)uint.MaxValue - 1,
            QuicVariableLengthInteger.MaxValue - 2,
        })
        {
            QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
            coordinator.SetNextApplicationPacketNumberForTests(startingPacketNumber);
            QuicTlsPacketProtectionMaterial material = QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial();
            byte[] applicationPayload = QuicS12P3TestSupport.CreatePingPayload();
            List<ulong> packetNumbers = [];

            for (int packetIndex = 0; packetIndex < 2; packetIndex++)
            {
                Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                    applicationPayload,
                    material,
                    keyPhase: false,
                    out ulong packetNumber,
                    out byte[] protectedPacket));

                Assert.NotEmpty(protectedPacket);
                Assert.DoesNotContain(packetNumber, packetNumbers);
                packetNumbers.Add(packetNumber);
                Assert.Equal(startingPacketNumber + (ulong)packetIndex + 1, coordinator.NextApplicationPacketNumber);
            }
        }

        QuicHandshakeFlowCoordinator exhaustedCoordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();
        exhaustedCoordinator.SetNextApplicationPacketNumberForTests(QuicVariableLengthInteger.MaxValue);
        QuicTlsPacketProtectionMaterial exhaustedMaterial = QuicS9P3TokenEmissionTestSupport.CreateOneRttMaterial();

        Assert.False(exhaustedCoordinator.TryBuildProtectedApplicationDataPacket(
            QuicS12P3TestSupport.CreatePingPayload(),
            exhaustedMaterial,
            keyPhase: false,
            out _,
            out _));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, exhaustedCoordinator.NextApplicationPacketNumber);
    }

    [Fact]
    [Requirement("RFC9000-S12-3-P7-S2-R02")]
    [Requirement("RFC9000-S12-3-P10-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberSpaceFuzz_StartsAtZeroAndAdvancesIndependentlyInEachSpace()
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] sourceConnectionId = [0x01, 0x02, 0x03, 0x04];

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection initialProtection));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial handshakeMaterial));
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial applicationMaterial));

        foreach (int payloadLength in new[] { 1, 20, 63 })
        {
            byte[] handshakeDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
            byte[] handshakeSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
            QuicHandshakeFlowCoordinator initialCoordinator = new(initialDestinationConnectionId, sourceConnectionId);
            QuicHandshakeFlowCoordinator handshakeCoordinator = new(
                handshakeDestinationConnectionId,
                handshakeSourceConnectionId);
            QuicHandshakeFlowCoordinator applicationCoordinator = QuicS17P1TestSupport.CreateApplicationCoordinator();

            byte[] initialPayload = QuicS12P3TestSupport.CreateSequentialBytes(0x10, payloadLength);
            byte[] handshakePayload = QuicS12P3TestSupport.CreateSequentialBytes(0x40, payloadLength);
            byte[] applicationPayload = payloadLength == 1
                ? QuicS12P3TestSupport.CreatePingPayload()
                : QuicS12P3TestSupport.CreateSequentialBytes(0x70, payloadLength);

            Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
                initialPayload,
                cryptoPayloadOffset: 0,
                initialProtection,
                out ulong firstInitialPacketNumber,
                out byte[] firstInitialPacket));
            Assert.True(initialCoordinator.TryBuildProtectedInitialPacket(
                initialPayload,
                cryptoPayloadOffset: (ulong)payloadLength,
                initialProtection,
                out ulong secondInitialPacketNumber,
                out byte[] secondInitialPacket));

            Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
                handshakePayload,
                cryptoPayloadOffset: 0,
                handshakeMaterial,
                out ulong firstHandshakePacketNumber,
                out byte[] firstHandshakePacket));
            Assert.True(handshakeCoordinator.TryBuildProtectedHandshakePacket(
                handshakePayload,
                cryptoPayloadOffset: (ulong)payloadLength,
                handshakeMaterial,
                out ulong secondHandshakePacketNumber,
                out byte[] secondHandshakePacket));

            Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                applicationMaterial,
                out ulong firstApplicationPacketNumber,
                out byte[] firstApplicationPacket));
            Assert.True(applicationCoordinator.TryBuildProtectedApplicationDataPacket(
                applicationPayload,
                applicationMaterial,
                out ulong secondApplicationPacketNumber,
                out byte[] secondApplicationPacket));

            Assert.Equal(0UL, firstInitialPacketNumber);
            Assert.Equal(1UL, secondInitialPacketNumber);
            Assert.Equal(0UL, firstHandshakePacketNumber);
            Assert.Equal(1UL, secondHandshakePacketNumber);
            Assert.Equal(0UL, firstApplicationPacketNumber);
            Assert.Equal(1UL, secondApplicationPacketNumber);
            Assert.False(firstInitialPacket.AsSpan().SequenceEqual(secondInitialPacket));
            Assert.False(firstHandshakePacket.AsSpan().SequenceEqual(secondHandshakePacket));
            Assert.False(firstApplicationPacket.AsSpan().SequenceEqual(secondApplicationPacket));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0712")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DuplicatePacketNumberFuzz_MergesDuplicatesWithinEachPacketNumberSpace()
    {
        foreach (QuicPacketNumberSpace packetNumberSpace in new[]
        {
            QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.ApplicationData,
        })
        {
            QuicSenderFlowController tracker = new();

            foreach (ulong packetNumber in new[] { 0UL, 1UL, 5UL, 63UL })
            {
                tracker.RecordIncomingPacket(
                    packetNumberSpace,
                    packetNumber,
                    ackEliciting: true,
                    receivedAtMicros: 1_000 + packetNumber);
                tracker.RecordIncomingPacket(
                    packetNumberSpace,
                    packetNumber,
                    ackEliciting: true,
                    receivedAtMicros: 1_500 + packetNumber);
            }

            Assert.True(tracker.TryBuildAckFrame(
                packetNumberSpace,
                nowMicros: 2_000,
                out QuicAckFrame frame));

            Assert.Equal(63UL, frame.LargestAcknowledged);
            Assert.Equal(0UL, frame.FirstAckRange);
            Assert.Equal(2, frame.AdditionalRanges.Length);
            Assert.Equal(0UL, frame.AdditionalRanges[0].AckRangeLength);
            Assert.Equal(1UL, frame.AdditionalRanges[1].AckRangeLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0715")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void NonFramePacketFuzz_KeepsVersionNegotiationRetryAndStatelessResetOutsideFrameParsing()
    {
        foreach (byte headerControlBits in new byte[] { 0x40, 0x4A, 0x7F })
        {
            byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits,
                destinationConnectionId: [0x11, 0x12],
                sourceConnectionId: [0x21],
                supportedVersions: [0x11223344u, 0x55667788u]);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out _));
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
            Assert.False(QuicFrameCodec.TryParsePaddingFrame(versionNegotiationPacket, out _));
            Assert.False(QuicFrameCodec.TryParsePingFrame(versionNegotiationPacket, out _));
        }

        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket();
        byte[] statelessResetPacket = QuicStatelessResetRequirementTestData.FormatDatagram(
            QuicStatelessResetRequirementTestData.CreateToken());

        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(retryPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(retryPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(statelessResetPacket, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(statelessResetPacket, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0716")]
    [Requirement("REQ-QUIC-RFC9000-0717")]
    [Requirement("REQ-QUIC-RFC9000-0718")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FramePayloadFuzz_ParsesMultipleFramesAndRejectsEmptyPayloads()
    {
        foreach (ulong maximumData in new[] { 0UL, 1UL, 63UL, 16_384UL })
        {
            byte[] packetPayload =
            [
                .. QuicFrameTestData.BuildPaddingFrame(),
                .. QuicFrameTestData.BuildPingFrame(),
                .. QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(maximumData)),
            ];

            Assert.True(QuicFrameCodec.TryParsePaddingFrame(packetPayload, out int paddingBytesConsumed));
            Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload[paddingBytesConsumed..], out int pingBytesConsumed));
            Assert.True(QuicFrameCodec.TryParseMaxDataFrame(
                packetPayload[(paddingBytesConsumed + pingBytesConsumed)..],
                out QuicMaxDataFrame parsedFrame,
                out int maxDataBytesConsumed));

            Assert.Equal(maximumData, parsedFrame.MaximumData);
            Assert.Equal(packetPayload.Length, paddingBytesConsumed + pingBytesConsumed + maxDataBytesConsumed);
        }

        Assert.False(QuicFrameCodec.TryParsePaddingFrame(ReadOnlySpan<byte>.Empty, out _));
        Assert.False(QuicFrameCodec.TryParsePingFrame(ReadOnlySpan<byte>.Empty, out _));
        Assert.False(QuicFrameCodec.TryParseMaxDataFrame(ReadOnlySpan<byte>.Empty, out _, out _));
    }
}
