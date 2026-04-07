namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0006")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0006
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P1-0006">An endpoint MUST NOT fail ECN validation as a result of processing an ACK frame that does not increase the largest acknowledged packet number.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P2-0003">Even if validation fails, an endpoint MAY revalidate ECN for the same path at any later time in the connection.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P2-0005">Network routing and path elements can change mid-connection; an endpoint MUST disable ECN if validation later fails.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryValidateAcknowledgedEcnCounts_AllowsReorderedAckFramesAndLaterRevalidation()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: false,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        Assert.False(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            reportedCounts: null,
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.True(validationFailed);
        Assert.False(state.IsEcnEnabled);

        state.ReenableEcn();

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }
}
