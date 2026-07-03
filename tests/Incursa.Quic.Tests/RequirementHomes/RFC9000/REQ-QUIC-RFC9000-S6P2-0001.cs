// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
public sealed class REQ_QUIC_RFC9000_S6P2_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0001">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet unless it has received and successfully processed any other packet or the Version Negotiation packet lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S6-2-P2-R01">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet, with the following two exceptions.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S6-2-P2-S2-R01">A client MUST discard a Version Negotiation packet that lists the QUIC version selected by the client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-21120001">Future versions of QUIC that use Version Negotiation packets MUST define a mechanism that is robust against version downgrade attacks.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("RFC9000-S6-2-P2-R01")]
    [Requirement("RFC9000-S6-2-P2-S2-R01")]
    [Requirement("REQ-QUIC-RFC9000-21120001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ShouldAbandonConnectionAttempt_OnlyWhenTheSelectedVersionIsNotAdvertised()
    {
        byte[] unsupportedVersionPacket = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(unsupportedVersionPacket, out QuicVersionNegotiationPacket packet));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));

        byte[] selectedVersionPacket = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            QuicVersionNegotiation.Version1,
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(selectedVersionPacket, out packet));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S6-2-P2-R01")]
    public void ShouldAbandonConnectionAttempt_ReturnsFalseWhenTheClientSupportsMultipleVersions()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1, 0x00000002],
            hasSuccessfullyProcessedAnotherPacket: false));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("RFC9000-S6-2-P2-R01")]
    [Requirement("RFC9000-S6-2-P2-S1-R01")]
    public void ShouldAbandonConnectionAttempt_ReturnsFalseAfterAnotherPacketHasAlreadyBeenProcessed()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        Assert.False(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            packet,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: true));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P2-0001">A client that supports only this version of QUIC MUST abandon the current connection attempt if it receives a Version Negotiation packet unless it has received and successfully processed any other packet or the Version Negotiation packet lists the QUIC version selected by the client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void Runtime_AbandonsUnsupportedVersionNegotiationAttempts()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), new FakeMonotonicClock(0));

        byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344);

        QuicConnectionTransitionResult transition = runtime.Transition(
            new QuicConnectionVersionNegotiationReceivedEvent(ObservedAtTicks: 1, packet),
            nowTicks: 1);

        Assert.True(transition.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.VersionNegotiation, runtime.TerminalState!.Value.Origin);

        QuicException exception = Assert.IsType<QuicException>(
            QuicClientConnectionHost.MapTerminalState(runtime.TerminalState.Value));
        Assert.Equal(QuicError.VersionNegotiationError, exception.QuicError);
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
