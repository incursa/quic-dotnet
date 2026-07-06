// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P16_DeferredFuzzClosure
{
    private static readonly byte[] HandshakeDestinationConnectionId =
    [
        0x71, 0x72, 0x73,
    ];

    private static readonly byte[] LocalSourceConnectionId =
    [
        0x81, 0x82, 0x83, 0x84,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0005")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetireConnectionIdFrameFuzz_RoundTripsSequenceNumberFieldAndRejectsTruncation()
    {
        Random random = new(0x5191_6005);
        Span<byte> destination = stackalloc byte[16];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            ulong sequenceNumber = iteration switch
            {
                0 => 0,
                1 => 63,
                2 => 64,
                3 => QuicVariableLengthInteger.MaxValue,
                _ => (ulong)random.Next(0, 1 << 20),
            };

            QuicRetireConnectionIdFrame frame = new(sequenceNumber);
            byte[] encoded = QuicFrameTestData.BuildRetireConnectionIdFrame(frame);

            Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
            Assert.Equal(sequenceNumber, parsed.SequenceNumber);
            Assert.Equal(encoded.Length, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatRetireConnectionIdFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(encoded.Length, bytesWritten);
            Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));

            if (encoded.Length > 1)
            {
                Assert.False(QuicFrameCodec.TryParseRetireConnectionIdFrame(encoded[..^1], out _, out _));
            }
        }
    }

    [Theory]
    [InlineData(11UL, 0x90)]
    [InlineData(281UL, 0xA0)]
    [InlineData(4096UL, 0xB0)]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LocallyRetiredConnectionIdFuzz_SendsRetireFrameForIssuedConnectionId(
        ulong connectionId,
        byte tokenStart)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(tokenStart);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: connectionId,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0).StateChanged);

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: connectionId),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        Assert.Contains(retired.Effects, effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire && retire.ConnectionId == connectionId);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(retired.Effects.OfType<QuicConnectionSendDatagramEffect>());
        QuicRetireConnectionIdFrame parsed = OpenRetireConnectionIdFrame(runtime, sendEffect.Datagram);
        Assert.Equal(connectionId, parsed.SequenceNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void NewConnectionIdDeliveryFuzz_AcceptsPeerIssuedConnectionIds()
    {
        QuicConnectionPeerConnectionIdState state = new();

        for (int sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                (ulong)sequenceNumber,
                retirePriorTo: 0,
                connectionIdStart: (byte)(0x40 + sequenceNumber),
                activeConnectionIdLimit: 6,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));

            Assert.Equal(default, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.Empty(retiredSequenceNumbers);
        }
    }

    [Theory]
    [InlineData(7UL, 7UL, false)]
    [InlineData(7UL, 8UL, true)]
    [InlineData(63UL, 64UL, true)]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetireConnectionIdSequenceFuzz_RejectsSequencesGreaterThanIssued(
        ulong issuedSequence,
        ulong retiredSequence,
        bool expectClosing)
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: issuedSequence,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(retiredSequence));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            retirePayload,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(expectClosing ? QuicConnectionPhase.Closing : QuicConnectionPhase.Active, runtime.Phase);
    }

    [Theory]
    [InlineData(1UL, 0UL)]
    [InlineData(1UL, 1UL)]
    [InlineData(4UL, 3UL)]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthPeerConnectionIdFuzz_DoesNotSendRetireConnectionIdFrame(
        ulong sequenceNumber,
        ulong retirePriorTo)
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        byte[] connectionId =
        [
            (byte)(0x91 + sequenceNumber),
            (byte)(0x92 + sequenceNumber),
            (byte)(0x93 + sequenceNumber),
        ];

        QuicConnectionTransitionResult result = ProcessPeerNewConnectionIdFrame(
            runtime,
            sequenceNumber,
            retirePriorTo,
            connectionId,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Empty(QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
    }

    private static QuicRetireConnectionIdFrame OpenRetireConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ReadOnlyMemory<byte> datagram)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(payload, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.True(bytesConsumed > 0);
        return parsed;
    }

    private static QuicConnectionRuntime CreateRuntime(ReadOnlySpan<byte> peerInitialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new("203.0.113.210", RemotePort: 443));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(HandshakeDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(LocalSourceConnectionId));

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = peerInitialSourceConnectionId.ToArray();
        peerTransportParameters.ActiveConnectionIdLimit = 3UL;

        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        return runtime;
    }

    private static QuicConnectionTransitionResult ProcessPeerNewConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        ulong retirePriorTo,
        ReadOnlySpan<byte> connectionId,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildNewConnectionIdFrame(new QuicNewConnectionIdFrame(
            sequenceNumber,
            retirePriorTo,
            connectionId,
            QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60)));

        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            payload,
            observedAtTicks);
    }
}
