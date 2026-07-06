// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S12P4_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0005")]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FramePayloadFuzz_KeepsFramesBoundedAndIdempotent()
    {
        Random random = new(0x5124_0005);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            QuicMaxDataFrame maxDataFrame = new((ulong)random.Next(0, 1 << 20));
            byte[] maxDataPacket = QuicFrameTestData.BuildMaxDataFrame(maxDataFrame);
            Assert.True(QuicFrameCodec.TryParseMaxDataFrame(maxDataPacket, out QuicMaxDataFrame firstMaxData, out int firstMaxDataBytes));
            Assert.True(QuicFrameCodec.TryParseMaxDataFrame(maxDataPacket, out QuicMaxDataFrame secondMaxData, out int secondMaxDataBytes));
            Assert.Equal(maxDataFrame.MaximumData, firstMaxData.MaximumData);
            Assert.Equal(firstMaxData.MaximumData, secondMaxData.MaximumData);
            Assert.Equal(firstMaxDataBytes, secondMaxDataBytes);
            Assert.False(QuicFrameCodec.TryParseMaxDataFrame(maxDataPacket[..^1], out _, out _));

            QuicAckFrame ackFrame = new()
            {
                FrameType = 0x02,
                LargestAcknowledged = (ulong)random.Next(1, 512),
                AckDelay = (ulong)random.Next(0, 128),
                FirstAckRange = 0,
            };
            byte[] ackPacket = QuicFrameTestData.BuildAckFrame(ackFrame);
            Assert.True(QuicFrameCodec.TryParseAckFrame(ackPacket, out QuicAckFrame firstAck, out int firstAckBytes));
            Assert.True(QuicFrameCodec.TryParseAckFrame(ackPacket, out QuicAckFrame secondAck, out int secondAckBytes));
            Assert.Equal(firstAck.LargestAcknowledged, secondAck.LargestAcknowledged);
            Assert.Equal(firstAck.AckDelay, secondAck.AckDelay);
            Assert.Equal(firstAckBytes, secondAckBytes);
            Assert.False(QuicFrameCodec.TryParseAckFrame(ackPacket[..^1], out _, out _));

            byte[] reason = [(byte)random.Next(0, 256), (byte)random.Next(0, 256)];
            byte[] closePacket = QuicFrameTestData.BuildConnectionCloseFrame(
                new QuicConnectionCloseFrame(QuicTransportErrorCode.ProtocolViolation, triggeringFrameType: 0x02, reason));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(closePacket, out QuicConnectionCloseFrame firstClose, out int firstCloseBytes));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(closePacket, out QuicConnectionCloseFrame secondClose, out int secondCloseBytes));
            Assert.Equal(firstClose.ErrorCode, secondClose.ErrorCode);
            Assert.Equal(firstClose.TriggeringFrameType, secondClose.TriggeringFrameType);
            Assert.Equal(firstCloseBytes, secondCloseBytes);
            Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(closePacket[..^1], out _, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FlagBearingFrameTypeFuzz_PreservesSelectedFrameFlags()
    {
        Random random = new(0x5124_0008);
        Span<byte> streamDestination = stackalloc byte[64];

        for (int iteration = 0; iteration < 64; iteration++)
        {
            bool includeEcn = random.Next(0, 2) == 0;
            QuicAckFrame ackFrame = new()
            {
                FrameType = includeEcn ? (byte)0x03 : (byte)0x02,
                LargestAcknowledged = (ulong)random.Next(1, 512),
                AckDelay = (ulong)random.Next(0, 128),
                FirstAckRange = 0,
            };

            if (includeEcn)
            {
                ackFrame.EcnCounts = new QuicEcnCounts(1, 2, 3);
            }

            byte[] ackPacket = QuicFrameTestData.BuildAckFrame(ackFrame);
            Assert.True(QuicFrameCodec.TryParseAckFrame(ackPacket, out QuicAckFrame parsedAck, out _));
            Assert.Equal(ackFrame.FrameType, parsedAck.FrameType);
            Assert.Equal(includeEcn, parsedAck.EcnCounts.HasValue);

            byte streamFrameType = (byte)(0x08 | (random.Next(0, 2) << 2) | (random.Next(0, 2) << 1) | random.Next(0, 2));
            byte[] streamData = [(byte)random.Next(0, 256), (byte)random.Next(0, 256)];
            ulong streamOffset = (streamFrameType & 0x04) != 0 ? 0x10UL : 0UL;
            Assert.True(QuicFrameCodec.TryFormatStreamFrame(streamFrameType, 0x04, streamOffset, streamData, streamDestination, out int streamBytesWritten));
            Assert.True(QuicStreamParser.TryParseStreamFrame(streamDestination[..streamBytesWritten], out QuicStreamFrame parsedStream));
            Assert.Equal(streamFrameType, parsedStream.FrameType);
            Assert.Equal((streamFrameType & 0x04) != 0, parsedStream.HasOffset);
            Assert.Equal((streamFrameType & 0x02) != 0, parsedStream.HasLength);
            Assert.Equal((streamFrameType & 0x01) != 0, parsedStream.IsFin);

            bool maxStreamsBidirectional = random.Next(0, 2) == 0;
            byte[] maxStreamsPacket = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(maxStreamsBidirectional, (ulong)random.Next(0, 512)));
            Assert.Equal(maxStreamsBidirectional ? 0x12 : 0x13, maxStreamsPacket[0]);
            Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(maxStreamsPacket, out QuicMaxStreamsFrame parsedMaxStreams, out _));
            Assert.Equal(maxStreamsBidirectional, parsedMaxStreams.IsBidirectional);

            bool streamsBlockedBidirectional = random.Next(0, 2) == 0;
            byte[] streamsBlockedPacket = QuicFrameTestData.BuildStreamsBlockedFrame(new QuicStreamsBlockedFrame(streamsBlockedBidirectional, (ulong)random.Next(0, 512)));
            Assert.Equal(streamsBlockedBidirectional ? 0x16 : 0x17, streamsBlockedPacket[0]);
            Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(streamsBlockedPacket, out QuicStreamsBlockedFrame parsedStreamsBlocked, out _));
            Assert.Equal(streamsBlockedBidirectional, parsedStreamsBlocked.IsBidirectional);

            bool applicationClose = random.Next(0, 2) == 0;
            byte[] closePacket = applicationClose
                ? QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame((ulong)random.Next(0, 512), []))
                : QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(QuicTransportErrorCode.NoError, triggeringFrameType: 0, []));
            Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(closePacket, out QuicConnectionCloseFrame parsedClose, out _));
            Assert.Equal(applicationClose, parsedClose.IsApplicationError);
            Assert.Equal(applicationClose ? 0x1D : 0x1C, parsedClose.FrameType);
        }
    }

    [Theory]
    [InlineData(false, 0UL)]
    [InlineData(true, 1UL)]
    [InlineData(true, 0x1234UL)]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialPacketConnectionCloseFuzz_AllowsOnlyTransportClose(
        bool applicationClose,
        ulong errorCode)
    {
        byte[] initialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0,
            0x3E, 0x51, 0x57, 0x08,
        ];
        QuicConnectionRuntime runtime = CreateServerRuntime(initialDestinationConnectionId);
        QuicConnectionPathIdentity path = new("203.0.113.70", RemotePort: 443);

        byte[] closePayload = applicationClose
            ? QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(errorCode, [(byte)errorCode]))
            : QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(QuicTransportErrorCode.NoError, triggeringFrameType: 0x02, [(byte)errorCode]));
        byte[] protectedInitialPacket = CreateProtectedInitialPacket(initialDestinationConnectionId, closePayload);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                path,
                protectedInitialPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(applicationClose ? QuicConnectionPhase.Closing : QuicConnectionPhase.Draining, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(
            applicationClose ? QuicConnectionCloseOrigin.Local : QuicConnectionCloseOrigin.Remote,
            runtime.TerminalState!.Value.Origin);
        Assert.Equal(
            applicationClose ? QuicTransportErrorCode.ProtocolViolation : QuicTransportErrorCode.NoError,
            runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Null(runtime.TerminalState.Value.Close.ApplicationErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0014")]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void CongestionMarkingFuzz_HonorsAckOnlyAndProbePacketMarkings()
    {
        Random random = new(0x5124_1415);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            ulong sentBytes = (ulong)random.Next(1, 4_096);
            QuicCongestionControlState ackOnlyState = new();
            ackOnlyState.RegisterPacketSent(sentBytes, isAckOnlyPacket: true);
            Assert.Equal(0UL, ackOnlyState.BytesInFlightBytes);

            QuicCongestionControlState normalState = new();
            normalState.RegisterPacketSent(sentBytes, isAckOnlyPacket: false);
            Assert.Equal(sentBytes, normalState.BytesInFlightBytes);

            QuicCongestionControlState probeState = new();
            probeState.RegisterPacketSent(probeState.CongestionWindowBytes);
            Assert.False(probeState.CanSend(1));
            Assert.True(probeState.CanSend(sentBytes, isProbePacket: true));
            Assert.True(probeState.TryRegisterLoss(
                sentBytes,
                sentAtMicros: (ulong)random.Next(1, 100_000),
                packetInFlight: true,
                isProbePacket: true));
            Assert.False(probeState.HasRecoveryStartTime);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FlowControlFuzz_EnforcesStreamFrameDataLimits()
    {
        Random random = new(0x5124_0016);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            ulong connectionLimit = (ulong)random.Next(1, 32);
            ulong streamLimit = (ulong)random.Next(1, 32);
            int length = random.Next(1, 40);
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: connectionLimit,
                localBidirectionalSendLimit: streamLimit);

            Assert.True(state.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            bool allowed = state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode);

            bool expectedAllowed = (ulong)length <= connectionLimit && (ulong)length <= streamLimit;
            Assert.Equal(expectedAllowed, allowed);
            Assert.Equal(default, errorCode);

            if (expectedAllowed)
            {
                Assert.Equal(default, dataBlockedFrame);
                Assert.Equal(default, streamDataBlockedFrame);
                Assert.Equal((ulong)length, state.ConnectionUniqueBytesSent);
            }
            else if (connectionLimit < (ulong)length)
            {
                Assert.True(
                    dataBlockedFrame.MaximumData == connectionLimit
                    || streamDataBlockedFrame.MaximumStreamData == streamLimit);
            }
            else
            {
                Assert.Equal(default, dataBlockedFrame);
                Assert.Equal(streamLimit, streamDataBlockedFrame.MaximumStreamData);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0017")]
    [Requirement("REQ-QUIC-RFC9000-S12P4-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FrameTypeErrorFuzz_RejectsUnknownAndNonMinimalFrameTypes()
    {
        byte[] unknownFrameTypes = [0x1F, 0x20, 0x21, 0x3F, 0x7E];

        foreach (byte unknownFrameType in unknownFrameTypes)
        {
            ReadOnlySpan<byte> packet = [unknownFrameType, 0x00, 0x00, 0x00];
            Assert.False(QuicFrameCodec.TryParsePaddingFrame(packet, out _));
            Assert.False(QuicFrameCodec.TryParsePingFrame(packet, out _));
            Assert.False(QuicFrameCodec.TryParseAckFrame(packet, out _, out _));
            Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(packet, out _, out _));
        }

        ulong[] frameTypes = [0x00, 0x01, 0x02, 0x10, 0x12, 0x16, 0x1A, 0x1C];
        foreach (ulong frameType in frameTypes)
        {
            byte[] nonMinimal = [.. QuicVarintTestData.EncodeWithLength(frameType, 2), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            Assert.False(QuicFrameCodec.TryParsePaddingFrame(nonMinimal, out _));
            Assert.False(QuicFrameCodec.TryParsePingFrame(nonMinimal, out _));
            Assert.False(QuicFrameCodec.TryParseAckFrame(nonMinimal, out _, out _));
            Assert.False(QuicFrameCodec.TryParseMaxDataFrame(nonMinimal, out _, out _));
            Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(nonMinimal, out _, out _));
            Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(nonMinimal, out _, out _));
            Assert.False(QuicFrameCodec.TryParsePathChallengeFrame(nonMinimal, out _, out _));
            Assert.False(QuicFrameCodec.TryParseConnectionCloseFrame(nonMinimal, out _, out _));
        }
    }

    private static byte[] CreateProtectedInitialPacket(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] paddedPlaintextPayload = new byte[Math.Max(plaintextPayload.Length, 24)];
        plaintextPayload.CopyTo(paddedPlaintextPayload);

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId:
            [
                0x21, 0x22, 0x23, 0x24,
            ],
            token: [],
            packetNumber:
            [
                0x01,
            ],
            plaintextPayload: paddedPlaintextPayload);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        return protectedPacket;
    }

    private static QuicConnectionRuntime CreateServerRuntime(ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            currentProbeTimeoutMicros: 100,
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        return runtime;
    }

    private sealed class FakeMonotonicClock(long ticks) : IMonotonicClock
    {
        public long Ticks { get; } = ticks;

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
