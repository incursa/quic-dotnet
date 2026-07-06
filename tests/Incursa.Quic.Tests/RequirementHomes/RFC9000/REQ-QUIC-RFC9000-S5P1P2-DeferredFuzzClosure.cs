// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S5P1P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MigratingPeerConnectionIdFuzz_ConsumesAnAvailablePeerIssuedConnectionIdForTheNewPath()
    {
        for (ulong sequenceNumber = 1; sequenceNumber < 12; sequenceNumber++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            byte[] initialDestinationConnectionId = CreateConnectionId((byte)(0x20 + sequenceNumber), 4);
            byte[] migrationConnectionId = CreateConnectionId((byte)(0x40 + sequenceNumber), 3);
            QuicConnectionPathIdentity originalPath = new($"203.0.113.{20 + sequenceNumber}", "198.51.100.20", 443, 61000 + (int)sequenceNumber);
            QuicConnectionPathIdentity migratedPath = new($"203.0.113.{40 + sequenceNumber}", "198.51.100.40", 443, 62000 + (int)sequenceNumber);

            Assert.True(state.TryAcceptNewConnectionId(
                new QuicNewConnectionIdFrame(
                    sequenceNumber,
                    retirePriorTo: 0,
                    migrationConnectionId,
                    QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x60 + sequenceNumber))),
                requiresZeroLengthDestinationConnectionId: false,
                activeConnectionIdLimit: 3,
                initialDestinationConnectionId,
                out QuicTransportErrorCode errorCode,
                out _,
                out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.Equal(0UL, state.CurrentDestinationConnectionIdSequence);

            state.BindCurrentDestinationConnectionIdToPath(originalPath);

            Assert.True(state.TryUseDestinationConnectionIdOnPath(
                migratedPath,
                activeConnectionIdLimit: 3,
                retireInactivePathConnectionIds: false,
                out errorCode,
                out bool destinationConnectionIdChanged,
                out ulong[] retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Empty(retiredSequenceNumbers);
            Assert.Equal(sequenceNumber, state.CurrentDestinationConnectionIdSequence);
            Assert.True(migrationConnectionId.AsSpan().SequenceEqual(state.CurrentDestinationConnectionId.Span));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetiredLocalConnectionIdFuzz_SendsRetireConnectionIdFramesWithTheRetiredSequence()
    {
        foreach (ulong connectionId in new ulong[] { 1, 7, 63, 64, 281, 4096 })
        {
            using QuicConnectionRuntime runtime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

            QuicConnectionTransitionResult issued = runtime.Transition(
                new QuicConnectionConnectionIdIssuedEvent(
                    ObservedAtTicks: 0,
                    ConnectionId: connectionId,
                    StatelessResetToken: QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken((byte)(0x70 + connectionId))),
                nowTicks: 0);
            Assert.True(issued.StateChanged);

            QuicConnectionTransitionResult retired = runtime.Transition(
                new QuicConnectionConnectionIdRetiredEvent(
                    ObservedAtTicks: 1,
                    ConnectionId: connectionId),
                nowTicks: 1);

            Assert.True(retired.StateChanged);
            Assert.Contains(
                retired.Effects,
                effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire
                    && retire.ConnectionId == connectionId);
            Assert.Equal([connectionId], QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, retired));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetireConnectionIdFrameFuzz_RoundTripsNoReuseSequenceRequests()
    {
        Span<byte> destination = stackalloc byte[16];

        foreach (ulong sequenceNumber in new ulong[] { 0, 1, 7, 63, 64, 1024, QuicVariableLengthInteger.MaxValue })
        {
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetirePriorToFuzz_PromptsRetirementOfLowerPeerConnectionIds()
    {
        for (ulong sequenceBase = 1; sequenceBase < 7; sequenceBase++)
        {
            QuicConnectionPeerConnectionIdState state = new();
            QuicTransportErrorCode errorCode = QuicTransportErrorCode.NoError;
            ulong[] retiredSequenceNumbers = [];
            for (ulong sequenceNumber = 1; sequenceNumber <= sequenceBase; sequenceNumber++)
            {
                Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                    state,
                    sequenceNumber,
                    retirePriorTo: 0,
                    connectionIdStart: (byte)(0x30 + (sequenceBase * 8) + sequenceNumber),
                    activeConnectionIdLimit: 8,
                    out errorCode,
                    out _,
                    out retiredSequenceNumbers));
                Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
                Assert.Empty(retiredSequenceNumbers);
            }

            Assert.True(QuicConnectionIdLifecycleTestSupport.TryAcceptNewConnectionId(
                state,
                sequenceBase + 1,
                retirePriorTo: sequenceBase + 1,
                connectionIdStart: (byte)(0x80 + sequenceBase),
                activeConnectionIdLimit: 8,
                out errorCode,
                out bool destinationConnectionIdChanged,
                out retiredSequenceNumbers));

            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(destinationConnectionIdChanged);
            Assert.Equal(Enumerable.Range(0, (int)sequenceBase + 1).Select(value => (ulong)value).ToArray(), retiredSequenceNumbers.Order().ToArray());
            Assert.Equal(sequenceBase + 1, state.CurrentDestinationConnectionIdSequence);
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
