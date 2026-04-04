namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP1-0005")]
public sealed class REQ_QUIC_RFC9002_SAP1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RecordPacketSent_TracksSentPacketsSeparatelyForEachPacketNumberSpace()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect1);
        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.NotEct);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RecordPacketSent_DoesNotLetCountsFromOnePacketNumberSpaceValidateAnotherSpace()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect1);

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));

        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecordPacketSent_AllowsBoundaryValidationForEachPacketNumberSpaceIndependently()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect1);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 1, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));

        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}
