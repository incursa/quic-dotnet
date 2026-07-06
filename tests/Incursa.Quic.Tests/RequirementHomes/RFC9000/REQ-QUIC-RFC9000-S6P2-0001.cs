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
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-21120001")]
    [Requirement("REQ-QUIC-RFC9000-S6P2-0001")]
    [Requirement("RFC9000-S6-2-P2-R01")]
    [Requirement("RFC9000-S6-2-P2-S1-R01")]
    [Requirement("RFC9000-S6-2-P2-S2-R01")]
    public void Fuzz_VersionNegotiationAbandonPolicyHonorsSelectedVersionAndStalePackets()
    {
        uint[][] clientSupportedVersionSets =
        [
            [QuicVersionNegotiation.Version1],
            [QuicVersionNegotiation.Version1, 0x00000002],
        ];
        byte[][] destinationConnectionIds =
        [
            [],
            [0x01],
            [0x01, 0x02, 0x03, 0x04],
            CreateConnectionId(20, 0xA0),
        ];
        byte[][] sourceConnectionIds =
        [
            [],
            [0xFA],
            CreateConnectionId(12, 0x40),
        ];
        uint[][] advertisedVersionSets =
        [
            [0x11223344],
            [0x11223344, 0x55667788],
            [QuicVersionNegotiation.Version1],
            [0x11223344, QuicVersionNegotiation.Version1],
            [QuicVersionNegotiation.CreateReservedVersion(0x12345678)],
        ];
        byte[] headerControlBits =
        [
            0x00,
            0x0C,
            0x4C,
            0x7F,
        ];

        int scenarioCount = 0;
        foreach (byte headerControl in headerControlBits)
        {
            foreach (byte[] destinationConnectionId in destinationConnectionIds)
            {
                foreach (byte[] sourceConnectionId in sourceConnectionIds)
                {
                    foreach (uint[] advertisedVersions in advertisedVersionSets)
                    {
                        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
                            headerControl,
                            destinationConnectionId,
                            sourceConnectionId,
                            advertisedVersions);

                        Assert.True(
                            QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
                        Assert.Equal(advertisedVersions.Length, packet.SupportedVersionCount);

                        foreach (uint[] clientSupportedVersions in clientSupportedVersionSets)
                        {
                            foreach (bool hasSuccessfullyProcessedAnotherPacket in new[] { false, true })
                            {
                                bool advertisedSelectedVersion = ContainsVersion(
                                    advertisedVersions,
                                    QuicVersionNegotiation.Version1);
                                bool expectedAbandon = clientSupportedVersions.Length <= 1
                                    && !hasSuccessfullyProcessedAnotherPacket
                                    && !advertisedSelectedVersion;

                                Assert.Equal(
                                    expectedAbandon,
                                    QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
                                        packet,
                                        QuicVersionNegotiation.Version1,
                                        clientSupportedVersions,
                                        hasSuccessfullyProcessedAnotherPacket));
                                scenarioCount++;
                            }
                        }
                    }
                }
            }
        }

        Assert.Equal(
            headerControlBits.Length
            * destinationConnectionIds.Length
            * sourceConnectionIds.Length
            * advertisedVersionSets.Length
            * clientSupportedVersionSets.Length
            * 2,
            scenarioCount);
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

    private static bool ContainsVersion(ReadOnlySpan<uint> versions, uint expected)
    {
        for (int index = 0; index < versions.Length; index++)
        {
            if (versions[index] == expected)
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] CreateConnectionId(int length, byte firstByte)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = (byte)(firstByte + index);
        }

        return connectionId;
    }
}
