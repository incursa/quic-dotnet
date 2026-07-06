// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ConnectionIdLegacy_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0215")]
    [Requirement("REQ-QUIC-RFC9000-0219")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LongHeaderConnectionIdFuzz_ParsesZeroLengthAndVariableHandshakeSourceConnectionIds()
    {
        byte[][] sourceConnectionIds =
        [
            [],
            [0x20],
            [0x21, 0x22, 0x23, 0x24],
            Enumerable.Range(0, QuicConnectionIdKey.MaximumLength).Select(value => (byte)(0x40 + value)).ToArray(),
        ];

        foreach (byte[] sourceConnectionId in sourceConnectionIds)
        {
            byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
                destinationConnectionId: [],
                sourceConnectionId: sourceConnectionId,
                protectedPayload: [(byte)(0xA0 + sourceConnectionId.Length)]);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(0, header.DestinationConnectionIdLength);
            Assert.True(header.DestinationConnectionId.IsEmpty);
            Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0220")]
    [Requirement("REQ-QUIC-RFC9000-0221")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ImplicitConnectionIdSequenceFuzz_RetiresInitialAndPreferredAddressConnectionIds()
    {
        for (int length = 1; length <= QuicConnectionIdKey.MaximumLength; length += 5)
        {
            QuicConnectionPeerConnectionIdState initialState = new();
            byte[] initialDestinationConnectionId = CreateConnectionId(0x10, length);

            Assert.True(initialState.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    1,
                    1,
                    CreateConnectionId(0x30, 3),
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x30)),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 3,
                initialDestinationConnectionId,
                out QuicTransportErrorCode errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Equal([0UL], retiredSequenceNumbers);

            QuicConnectionPeerConnectionIdState preferredState = new();
            byte[] preferredConnectionId = CreateConnectionId(0x50, length);
            QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: preferredConnectionId);

            Assert.True(preferredState.TryAcceptPreferredAddressConnectionId(
                preferredAddress,
                activeConnectionIdLimit: 3,
                initialDestinationConnectionId,
                out errorCode,
                out destinationConnectionIdChanged));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(destinationConnectionIdChanged);

            Assert.True(preferredState.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    2,
                    2,
                    CreateConnectionId(0x70, 3),
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 3,
                initialDestinationConnectionId,
                out errorCode,
                out destinationConnectionIdChanged,
                out retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Equal([0UL, 1UL], retiredSequenceNumbers);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0222")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LocalConnectionIdReplenishmentFuzz_IssuesTheNextSequenceWhenPeerRetiresAnActiveId()
    {
        for (ulong sequenceNumber = 1; sequenceNumber <= 4; sequenceNumber++)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
                peerActiveConnectionIdLimit: 3);
            byte[] issuedConnectionId = CreateConnectionId((byte)(0x80 + sequenceNumber), 4);

            Assert.True(runtime.Transition(
                new QuicConnectionConnectionIdIssuedEvent(
                    ObservedAtTicks: 0,
                    ConnectionId: sequenceNumber,
                    StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x80 + sequenceNumber)),
                    ConnectionIdBytes: issuedConnectionId),
                nowTicks: 0).StateChanged);

            QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
                runtime,
                runtime.ActivePath!.Value.Identity,
                issuedConnectionId,
                QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(sequenceNumber)),
                observedAtTicks: (long)sequenceNumber);

            QuicNewConnectionIdFrameProofSnapshot replacementFrame =
                Assert.Single(QuicConnectionIdLifecycleTestSupport.GetNewConnectionIdFrames(runtime, result));

            Assert.Equal(sequenceNumber + 1, replacementFrame.SequenceNumber);
            Assert.Equal(0UL, replacementFrame.RetirePriorTo);
            Assert.NotEmpty(replacementFrame.ConnectionId);
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
