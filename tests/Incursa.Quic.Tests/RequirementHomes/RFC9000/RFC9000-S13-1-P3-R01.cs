// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S13-1-P3-R01">An endpoint SHOULD treat receipt of an acknowledgment for a packet it did not send as a connection error of type PROTOCOL_VIOLATION, if it is able to detect the condition.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S13-1-P3-R01")]
public sealed class REQ_QUIC_RFC9000_0752
{
    [Fact]
    [Requirement("RFC9000-S13-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryAcknowledgePacket_RemovesASentPacketFromTracking()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packetBytes = QuicFrameTestData.BuildPingFrame();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)packetBytes.Length,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packetBytes));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
        Assert.False(runtime.HasAckElicitingPacketsInFlight);
    }

    [Fact]
    [Requirement("RFC9000-S13-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_RejectsAnUnsentPacket()
    {
        QuicConnectionSendRuntime runtime = new();

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Empty(runtime.SentPackets);
    }

    [Fact]
    [Requirement("RFC9000-S13-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcknowledgePacket_DoesNotMatchASentPacketAcrossPacketNumberSpaces()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packetBytes = QuicFrameTestData.BuildPingFrame();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: (ulong)packetBytes.Length,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packetBytes));

        Assert.False(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            8,
            handshakeConfirmed: true));
        Assert.Single(runtime.SentPackets);
        Assert.True(runtime.SentPackets.ContainsKey(new QuicConnectionSentPacketKey(
            QuicPacketNumberSpace.ApplicationData,
            8)));
    }

    [Fact]
    [Requirement("RFC9000-S13-1-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryAcknowledgePacket_OnlyAcceptsPreviouslySentPacketsInTheSamePacketNumberSpace()
    {
        (QuicPacketNumberSpace SentSpace, ulong SentPacketNumber, QuicPacketNumberSpace AckSpace, ulong AckPacketNumber, bool Expected)[] cases =
        [
            (QuicPacketNumberSpace.Initial, 1, QuicPacketNumberSpace.Initial, 1, true),
            (QuicPacketNumberSpace.Handshake, 2, QuicPacketNumberSpace.Handshake, 2, true),
            (QuicPacketNumberSpace.ApplicationData, 3, QuicPacketNumberSpace.ApplicationData, 3, true),
            (QuicPacketNumberSpace.ApplicationData, 4, QuicPacketNumberSpace.ApplicationData, 5, false),
            (QuicPacketNumberSpace.ApplicationData, 6, QuicPacketNumberSpace.Handshake, 6, false),
            (QuicPacketNumberSpace.Handshake, 7, QuicPacketNumberSpace.Initial, 7, false),
        ];

        foreach ((QuicPacketNumberSpace sentSpace, ulong sentPacketNumber, QuicPacketNumberSpace ackSpace, ulong ackPacketNumber, bool expected) in cases)
        {
            QuicConnectionSendRuntime runtime = new();
            byte[] packetBytes = QuicFrameTestData.BuildPingFrame();

            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                sentSpace,
                sentPacketNumber,
                PayloadBytes: (ulong)packetBytes.Length,
                SentAtMicros: 1_000 + sentPacketNumber,
                AckEliciting: true,
                Retransmittable: true,
                PacketBytes: packetBytes));

            Assert.Equal(expected, runtime.TryAcknowledgePacket(
                ackSpace,
                ackPacketNumber,
                handshakeConfirmed: true));

            if (expected)
            {
                Assert.Empty(runtime.SentPackets);
                Assert.False(runtime.HasAckElicitingPacketsInFlight);
            }
            else
            {
                Assert.True(runtime.SentPackets.ContainsKey(new QuicConnectionSentPacketKey(sentSpace, sentPacketNumber)));
                Assert.True(runtime.HasAckElicitingPacketsInFlight);
            }
        }
    }
}
