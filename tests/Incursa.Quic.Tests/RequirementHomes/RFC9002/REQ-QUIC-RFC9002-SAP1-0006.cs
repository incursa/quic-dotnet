namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SAP1-0006")]
public sealed class REQ_QUIC_RFC9002_SAP1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_ProcessesEachPacketNumberSpaceIndependently()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect0);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
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
    public void TryValidateAcknowledgedEcnCounts_DoesNotCrossValidateAgainstAnotherPacketNumberSpace()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));

        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryValidateAcknowledgedEcnCounts_LeavesOtherSpacesUntouchedWhenTheLargestAckDoesNotIncrease()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect0);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: false,
            out bool validationFailed));

        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));

        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}
