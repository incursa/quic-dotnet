// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S12P3_DeferredFuzzClosure
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0,
        0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] SourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialPacketProtectionFuzz_UsesPacketNumberWhenDerivingNonce()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        for (byte packetNumber = 0; packetNumber < 8; packetNumber++)
        {
            byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
                destinationConnectionId: InitialDestinationConnectionId,
                sourceConnectionId: SourceConnectionId,
                token: [],
                packetNumber: [packetNumber],
                plaintextPayload: QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x10 + packetNumber), 20));
            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];

            Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
            Assert.Equal(protectedPacket.Length, protectedBytesWritten);
            Assert.True(receiverProtection.TryOpen(protectedPacket, new byte[plaintextPacket.Length], out int openedBytesWritten));
            Assert.Equal(plaintextPacket.Length, openedBytesWritten);

            byte[] tamperedPacketNumber = protectedPacket.ToArray();
            tamperedPacketNumber[GetInitialPacketNumberOffset(plaintextPacket)] ^= 0x01;

            Assert.False(receiverProtection.TryOpen(tamperedPacketNumber, new byte[plaintextPacket.Length], out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberSpaceFuzz_MaintainsIndependentSendAndReceiveAckSpaces()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, SourceConnectionId);
        QuicSenderFlowController receiver = new();
        QuicSenderFlowController sender = new();

        for (ulong index = 0; index < 8; index++)
        {
            Assert.True(coordinator.TryBuildProtectedInitialPacket(
                QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x20 + index), 20),
                cryptoPayloadOffset: index * 20,
                protection,
                out ulong sentPacketNumber,
                out byte[] protectedPacket));
            Assert.Equal(index, sentPacketNumber);

            sender.RecordPacketSent(
                QuicPacketNumberSpace.Initial,
                sentPacketNumber,
                sentBytes: (ulong)protectedPacket.Length,
                sentAtMicros: 1_000 + index,
                ackEliciting: true);
            receiver.RecordIncomingPacket(
                index % 2 == 0 ? QuicPacketNumberSpace.Initial : QuicPacketNumberSpace.Handshake,
                packetNumber: 100 + index,
                ackEliciting: true,
                receivedAtMicros: 2_000 + index);
        }

        QuicAckFrame initialAck = new()
        {
            LargestAcknowledged = 7,
            AckDelay = 0,
            FirstAckRange = 7,
            AdditionalRanges = [],
        };

        Assert.False(sender.TryProcessAckFrame(QuicPacketNumberSpace.Handshake, initialAck, ackReceivedAtMicros: 3_000, pathValidated: true));
        Assert.True(sender.TryProcessAckFrame(QuicPacketNumberSpace.Initial, initialAck, ackReceivedAtMicros: 3_100, pathValidated: true));
        Assert.False(sender.TryRegisterLoss(QuicPacketNumberSpace.Initial, packetNumber: 7, sentAtMicros: 1_007));

        Assert.True(receiver.TryBuildAckFrame(QuicPacketNumberSpace.Initial, nowMicros: 4_000, out QuicAckFrame receiveInitialAck));
        Assert.True(receiver.TryBuildAckFrame(QuicPacketNumberSpace.Handshake, nowMicros: 4_000, out QuicAckFrame receiveHandshakeAck));
        Assert.Equal(106UL, receiveInitialAck.LargestAcknowledged);
        Assert.Equal(107UL, receiveHandshakeAck.LargestAcknowledged);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberlessHeaderFuzz_RejectsVersionNegotiationAndRetryAsPacketNumberSpaces()
    {
        for (int iteration = 0; iteration < 16; iteration++)
        {
            byte[] versionNegotiationPacket = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: (byte)(0x40 | (iteration & 0x0F)),
                destinationConnectionId: [(byte)(0x10 + iteration), 0x11],
                sourceConnectionId: [(byte)(0x20 + iteration)],
                supportedVersions: [0x1122_3300u + (uint)iteration, 0x5566_7700u + (uint)iteration]);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(versionNegotiationPacket, out QuicVersionNegotiationPacket versionNegotiationHeader));
            Assert.Equal(2, versionNegotiationHeader.SupportedVersionCount);
            Assert.False(QuicPacketParser.TryGetPacketNumberSpace(versionNegotiationPacket, out _));
        }

        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket();
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket retryHeader));
        Assert.Equal((byte)0x03, retryHeader.LongPacketTypeBits);
        Assert.False(QuicPacketParser.TryGetPacketNumberSpace(retryPacket, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberExhaustionFuzz_AllowsStatelessResetFromRetainedRoute()
    {
        for (int iteration = 0; iteration < 4; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2, maximumStatelessResetEmissionsPerRemoteAddress: 1);
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{60 + iteration}", RemotePort: 443);
            byte[] routeConnectionId = [0x66, 0x09, 0xA0, (byte)(0x20 + iteration)];
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0xD0 + iteration));

            ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
                endpoint,
                runtime,
                handle,
                pathIdentity,
                routeConnectionId,
                6909UL + (ulong)iteration,
                token);
            DiscardRuntimeForPacketNumberExhaustion(endpoint, runtime, handle);

            byte[] triggeringPacket = QuicStatelessResetEndpointHostTestSupport.CreateRetainedRouteShortHeaderDatagram(
                routeConnectionId,
                triggeringPacketLength: QuicStatelessReset.MinimumDatagramLength + iteration);

            QuicConnectionStatelessResetEmissionResult emission = endpoint.TryCreateStatelessResetDatagramForPacket(
                triggeringPacket,
                pathIdentity,
                hasLoopPreventionState: true);

            Assert.True(emission.Emitted);
            Assert.Equal(pathIdentity, emission.PathIdentity);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(emission.Datagram.Span, token);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P3-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DuplicateSuppressionFuzz_RecordsPacketsOnlyAfterProtectionIsRemoved()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        QuicSenderFlowController tracker = new();

        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
                QuicS12P3TestSupport.CreatePingPayload(),
                material,
                out byte[] protectedPacket));

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                material,
                out byte[] openedPacket,
                out int payloadOffset,
                out _,
                out _));
            ulong packetNumber = ParsePacketNumber(openedPacket, payloadOffset);

            tracker.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 1_000 + (ulong)iteration);
            tracker.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: 2_000 + (ulong)iteration);

            byte[] tamperedPacket = protectedPacket.ToArray();
            tamperedPacket[^1] ^= 0x01;
            Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(tamperedPacket, material, out _, out _, out _, out _));
        }

        Assert.True(tracker.TryBuildAckFrame(QuicPacketNumberSpace.ApplicationData, nowMicros: 3_000, out QuicAckFrame ackFrame));
        Assert.Equal(7UL, ackFrame.LargestAcknowledged);
        Assert.Equal(7UL, ackFrame.FirstAckRange);
        Assert.Empty(ackFrame.AdditionalRanges);
    }

    private static int GetInitialPacketNumberOffset(ReadOnlySpan<byte> plaintextPacket)
    {
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            plaintextPacket,
            out _,
            out _,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));

        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes));
        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + checked((int)tokenLength));
        Assert.True(QuicVariableLengthInteger.TryParse(afterToken, out _, out int lengthFieldBytes));

        return QuicHeaderTestData.GetLongHeaderPayloadOffset(plaintextPacket)
            + tokenLengthBytes
            + checked((int)tokenLength)
            + lengthFieldBytes;
    }

    private static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, SourceConnectionId);
        Assert.True(coordinator.TrySetDestinationConnectionId(InitialDestinationConnectionId));
        return coordinator;
    }

    private static ulong ParsePacketNumber(ReadOnlySpan<byte> openedPacket, int payloadOffset)
    {
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        int packetNumberLength = parsedHeader.PacketNumberLengthBits + 1;
        ReadOnlySpan<byte> packetNumberBytes = openedPacket.Slice(payloadOffset - packetNumberLength, packetNumberLength);

        ulong packetNumber = 0;
        foreach (byte packetNumberByte in packetNumberBytes)
        {
            packetNumber = (packetNumber << 8) | packetNumberByte;
        }

        return packetNumber;
    }

    private static void ConfigurePacketNumberExhaustionRetainedRouteEndpoint(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> routeConnectionId,
        ulong resetConnectionId,
        ReadOnlySpan<byte> token)
    {
        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeConnectionId, statelessResetConnectionId: resetConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
        Assert.True(endpoint.TryRegisterStatelessResetToken(handle, resetConnectionId, token));
    }

    private static void DiscardRuntimeForPacketNumberExhaustion(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionRuntime runtime,
        QuicConnectionHandle handle)
    {
        runtime.HandshakeFlowCoordinator.SetNextApplicationPacketNumberForTests(QuicVariableLengthInteger.MaxValue);

        List<QuicConnectionEffect>? effects = [];
        Assert.True(runtime.TrySendRecoveryPingProbe(ref effects));
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);

        QuicConnectionDiscardConnectionStateEffect discardEffect = Assert.Single(effects!.OfType<QuicConnectionDiscardConnectionStateEffect>());
        Assert.True(endpoint.TryApplyEffect(handle, discardEffect));
    }
}
