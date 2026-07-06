// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S5P1P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ConnectionIdSequenceFuzz_RoundTripsNewAndRetireConnectionIdSequenceNumbers()
    {
        Span<byte> formatted = stackalloc byte[64];

        for (ulong sequenceNumber = 0; sequenceNumber < 16; sequenceNumber++)
        {
            byte[] connectionId = CreateConnectionId((byte)(0x20 + sequenceNumber), 1 + (int)(sequenceNumber % QuicConnectionIdKey.MaximumLength));
            byte[] token = QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x60 + sequenceNumber));
            QuicNewConnectionIdFrame frame = new(
                sequenceNumber,
                retirePriorTo: sequenceNumber / 2,
                connectionId,
                token);
            byte[] encoded = QuicFrameTestData.BuildNewConnectionIdFrame(frame);

            Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(sequenceNumber, parsed.SequenceNumber);
            Assert.Equal(frame.RetirePriorTo, parsed.RetirePriorTo);
            Assert.True(connectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
            Assert.True(token.AsSpan().SequenceEqual(parsed.StatelessResetToken));

            Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, formatted, out int bytesWritten));
            Assert.True(encoded.AsSpan().SequenceEqual(formatted[..bytesWritten]));

            byte[] retireEncoded = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(sequenceNumber));
            Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(retireEncoded, out QuicRetireConnectionIdFrame retire, out int retireBytesConsumed));
            Assert.Equal(sequenceNumber, retire.SequenceNumber);
            Assert.Equal(retireEncoded.Length, retireBytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void UnsequencedInitialAndRetryConnectionIdFuzz_DoNotReplaceImplicitInitialSequence()
    {
        for (ulong sequenceNumber = 1; sequenceNumber < 12; sequenceNumber++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            byte[] implicitInitialConnectionId = CreateConnectionId((byte)(0x30 + sequenceNumber), 4);
            byte[] newlyIssuedConnectionId = CreateConnectionId((byte)(0x50 + sequenceNumber), 3);
            QuicNewConnectionIdFrame frame = new(
                sequenceNumber,
                retirePriorTo: 0,
                newlyIssuedConnectionId,
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x70 + sequenceNumber)));

            Assert.True(state.TryAcceptNewConnectionId(
                frame,
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 3,
                implicitInitialConnectionId,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);
            Assert.Empty(retiredSequenceNumbers);
            Assert.Equal(0UL, state.CurrentDestinationConnectionIdSequence);
            Assert.True(implicitInitialConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void IssuedConnectionIdRouteFuzz_RemainsRoutableUntilPeerRetiresIt()
    {
        for (ulong connectionIdSequence = 1; connectionIdSequence < 12; connectionIdSequence++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{100 + connectionIdSequence}", RemotePort: 443);
            byte[] issuedConnectionId = CreateConnectionId((byte)(0x80 + connectionIdSequence), 3 + (int)(connectionIdSequence % 4));
            byte[] routedDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [.. issuedConnectionId, 0xA1]);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

            QuicConnectionTransitionResult issued = IssueConnectionId(runtime, connectionIdSequence, issuedConnectionId);
            Assert.True(issued.StateChanged);
            ApplyEndpointEffects(endpoint, handle, issued.Effects);

            QuicConnectionIngressResult beforeRetirement = endpoint.ReceiveDatagram(routedDatagram, pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, beforeRetirement.Disposition);
            Assert.Equal(handle, beforeRetirement.Handle);

            QuicConnectionTransitionResult retired = runtime.Transition(
                new QuicConnectionConnectionIdRetiredEvent(
                    ObservedAtTicks: 10 + (long)connectionIdSequence,
                    ConnectionId: connectionIdSequence),
                nowTicks: 10 + (long)connectionIdSequence);
            Assert.True(retired.StateChanged);
            ApplyEndpointEffects(endpoint, handle, retired.Effects);

            QuicConnectionIngressResult afterRetirement = endpoint.ReceiveDatagram(routedDatagram, pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, afterRetirement.Disposition);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ActiveConnectionIdRouteFuzz_RoutesShortAndLongHeaderPackets()
    {
        for (ulong connectionIdSequence = 1; connectionIdSequence < 12; connectionIdSequence++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{130 + connectionIdSequence}", RemotePort: 443);
            byte[] issuedConnectionId = CreateConnectionId((byte)(0xA0 + connectionIdSequence), 3 + (int)(connectionIdSequence % 5));

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));

            QuicConnectionTransitionResult issued = IssueConnectionId(runtime, connectionIdSequence, issuedConnectionId);
            Assert.True(issued.StateChanged);
            ApplyEndpointEffects(endpoint, handle, issued.Effects);

            QuicConnectionIngressResult shortHeader = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, [.. issuedConnectionId, 0xB1]),
                pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, shortHeader.Disposition);
            Assert.Equal(handle, shortHeader.Handle);

            QuicConnectionIngressResult longHeader = endpoint.ReceiveDatagram(
                QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
                    destinationConnectionId: issuedConnectionId,
                    sourceConnectionId: [(byte)(0xC0 + connectionIdSequence)],
                    protectedPayload: [(byte)(0xD0 + connectionIdSequence)]),
                pathIdentity);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, longHeader.Disposition);
            Assert.Equal(handle, longHeader.Handle);
        }
    }

    private static QuicConnectionTransitionResult IssueConnectionId(
        QuicConnectionRuntime runtime,
        ulong connectionIdSequence,
        ReadOnlySpan<byte> issuedConnectionId)
    {
        return runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: (long)connectionIdSequence,
                ConnectionId: connectionIdSequence,
                StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x40 + connectionIdSequence)),
                ConnectionIdBytes: issuedConnectionId.ToArray()),
            nowTicks: (long)connectionIdSequence);
    }

    private static void ApplyEndpointEffects(
        QuicConnectionRuntimeEndpoint endpoint,
        QuicConnectionHandle handle,
        IEnumerable<QuicConnectionEffect> effects)
    {
        foreach (QuicConnectionEffect effect in effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }
    }

    private static byte[] CreateConnectionId(byte startValue, int length)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(startValue + index));
        }

        return connectionId;
    }
}
