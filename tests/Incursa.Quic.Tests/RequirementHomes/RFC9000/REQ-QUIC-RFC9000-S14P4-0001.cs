namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P4-0001">PMTU probes MUST be ack-eliciting packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P4-0001")]
public sealed class REQ_QUIC_RFC9000_S14P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TrackSentPacket_RetainsAckElicitingProbePackets()
    {
        QuicConnectionSendRuntime runtime = new();

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            Retransmittable: false,
            ProbePacket: true));

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> trackedPacket = Assert.Single(runtime.SentPackets);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, trackedPacket.Key.PacketNumberSpace);
        Assert.Equal(7UL, trackedPacket.Key.PacketNumber);
        Assert.True(trackedPacket.Value.ProbePacket);
        Assert.True(trackedPacket.Value.AckEliciting);
        Assert.False(trackedPacket.Value.Retransmittable);
        Assert.True(runtime.HasAckElicitingPacketsInFlight);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrackSentPacket_RejectsProbePacketsThatAreNotAckEliciting()
    {
        QuicConnectionSendRuntime runtime = new();

        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            runtime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: 7,
                PayloadBytes: 1_200,
                SentAtMicros: 100,
                AckEliciting: false,
                Retransmittable: false,
                ProbePacket: true)));

        Assert.Equal("packet", exception.ParamName);
        Assert.Contains("Probe packets must be ack-eliciting packets.", exception.Message);
        Assert.Empty(runtime.SentPackets);
        Assert.False(runtime.HasAckElicitingPacketsInFlight);
    }
}
