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
