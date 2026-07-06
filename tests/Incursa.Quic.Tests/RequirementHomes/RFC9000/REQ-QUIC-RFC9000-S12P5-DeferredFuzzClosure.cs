// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S12P5_DeferredFuzzClosure
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberSpaceFuzz_MapsHandshakeFramesAndApplicationFramesToTheirPacketSpaces()
    {
        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] cryptoPayload = QuicFrameTestData.BuildCryptoFrame(
                new QuicCryptoFrame((ulong)iteration, QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x20 + iteration), 1 + (iteration % 16))));
            byte[] initialPacket = BuildProtectedInitialPacket(cryptoPayload);
            byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: cryptoPayload);
            byte[] applicationPayload = (iteration & 1) == 0
                ? QuicFrameTestData.BuildPingFrame()
                : QuicStreamTestData.BuildStreamFrame(
                    QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask,
                    streamId: 0,
                    QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x60 + iteration), 1 + (iteration % 8)));
            byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader((byte)(iteration & 0x03), applicationPayload);

            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out QuicPacketNumberSpace initialSpace));
            Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace handshakeSpace));
            Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace applicationSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, applicationSpace);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P5-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void AckFrameFuzz_AcknowledgesPacketsOnlyWithinThePacketNumberSpaceContainingTheAck()
    {
        foreach (QuicPacketNumberSpace packetNumberSpace in new[]
        {
            QuicPacketNumberSpace.Initial,
            QuicPacketNumberSpace.Handshake,
            QuicPacketNumberSpace.ApplicationData,
        })
        {
            for (ulong packetNumber = 0; packetNumber < 32; packetNumber++)
            {
                QuicAckFrame ackFrame = new()
                {
                    LargestAcknowledged = packetNumber,
                    AckDelay = 0,
                    FirstAckRange = 0,
                    AdditionalRanges = [],
                };

                AssertAckedInSpace(packetNumberSpace, ackFrame, packetNumber);
                AssertNotAckedFromDifferentSpace(packetNumberSpace, ackFrame, packetNumber);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P5-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttFrameLegalityFuzz_ForbiddenFramesCloseWithProtocolViolation()
    {
        foreach ((byte[] Payload, ulong TriggeringFrameType) in CreateForbiddenZeroRttPayloads())
        {
            QuicTlsPacketProtectionMaterial zeroRttMaterial = QuicS17P2P3TestSupport.CreatePacketProtectionMaterial(
                QuicTlsEncryptionLevel.ZeroRtt);
            using QuicConnectionRuntime runtime = CreateServerRuntimeWithZeroRttOpenMaterial(zeroRttMaterial);
            QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();

            Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
                Payload,
                zeroRttMaterial,
                out byte[] protectedPacket));

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 2,
                    QuicS17P2P3TestSupport.BootstrapPath,
                    protectedPacket),
                nowTicks: 2);

            Assert.True(result.StateChanged);
            Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
            Assert.True(runtime.TerminalState.HasValue);
            Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState.Value.Origin);
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
            Assert.Equal(TriggeringFrameType, runtime.TerminalState.Value.Close.TriggeringFrameType);
        }
    }

    private static byte[] BuildProtectedInitialPacket(ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            payload,
            cryptoPayloadOffset: 0,
            protection,
            out byte[] protectedPacket));

        return protectedPacket;
    }

    private static void AssertAckedInSpace(
        QuicPacketNumberSpace packetNumberSpace,
        QuicAckFrame ackFrame,
        ulong packetNumber)
    {
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(packetNumberSpace, packetNumber, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);

        Assert.True(sender.TryProcessAckFrame(packetNumberSpace, ackFrame, ackReceivedAtMicros: 2_000, pathValidated: true));
        Assert.False(sender.TryRegisterLoss(packetNumberSpace, packetNumber, sentAtMicros: 1_000));
    }

    private static void AssertNotAckedFromDifferentSpace(
        QuicPacketNumberSpace ackPacketNumberSpace,
        QuicAckFrame ackFrame,
        ulong packetNumber)
    {
        QuicPacketNumberSpace sentPacketNumberSpace = ackPacketNumberSpace == QuicPacketNumberSpace.Initial
            ? QuicPacketNumberSpace.Handshake
            : QuicPacketNumberSpace.Initial;
        QuicSenderFlowController sender = new();
        sender.RecordPacketSent(sentPacketNumberSpace, packetNumber, sentBytes: 1_200, sentAtMicros: 1_000, ackEliciting: true);

        Assert.False(sender.TryProcessAckFrame(ackPacketNumberSpace, ackFrame, ackReceivedAtMicros: 2_000, pathValidated: true));
        Assert.True(sender.TryRegisterLoss(sentPacketNumberSpace, packetNumber, sentAtMicros: 1_000));
    }

    private static IEnumerable<(byte[] Payload, ulong TriggeringFrameType)> CreateForbiddenZeroRttPayloads()
    {
        yield return (QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
        }), QuicPacketFrameLegality.ApplicationPacketAckFrameType);
        yield return (QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA])), QuicPacketFrameLegality.ApplicationPacketCryptoFrameType);
        yield return (QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame([0xBB])), 0x07UL);
        yield return (QuicFrameTestData.BuildHandshakeDoneFrame(), QuicPacketFrameLegality.HandshakePacketHandshakeDoneFrameType);
    }

    private static QuicConnectionRuntime CreateServerRuntimeWithZeroRttOpenMaterial(
        QuicTlsPacketProtectionMaterial zeroRttMaterial)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(
                isServer: true,
                connectionReceiveLimit: 256,
                incomingBidirectionalStreamLimit: 4,
                localBidirectionalReceiveLimit: 64,
                peerBidirectionalReceiveLimit: 64),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P3TestSupport.PacketSourceConnectionId));
        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P3TestSupport.PacketConnectionId));
        Assert.True(runtime.InitializeActivePath(QuicS17P2P3TestSupport.BootstrapPath, 1200, 0));
        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: zeroRttMaterial)),
            nowTicks: 1).StateChanged);
        Assert.True(runtime.IsEarlyDataAdmissionOpen);
        return runtime;
    }
}
