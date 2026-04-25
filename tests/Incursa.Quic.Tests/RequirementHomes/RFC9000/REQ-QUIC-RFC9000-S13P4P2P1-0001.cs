namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0001")]
public sealed class REQ_QUIC_RFC9000_S13P4P2P1_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4-0001">QUIC endpoints MAY use ECN [RFC3168] to detect and respond to network congestion.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2-0001">To ensure connectivity in the presence of such devices, an endpoint MUST validate the ECN counts for each network path and disable the use of ECN on that path if errors are detected.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2-0006">Implementations that use the ECT(1) codepoint MUST perform ECN validation using the reported ECT(1) counts.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P1-0006">Each packet number space MUST maintain separate acknowledgment state and separate ECN counts.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P1-0001">An endpoint that receives an ACK frame with ECN counts MUST validate the counts before using them.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P1-0004">ECN validation MUST fail if the sum of the increase in ECT(0) and ECN-CE counts is less than the number of newly acknowledged packets that were originally sent with an ECT(0) marking.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P1-0005">ECN validation MUST fail if the sum of the increases to ECT(1) and ECN-CE counts is less than the number of newly acknowledged packets sent with an ECT(1) marking.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P2-0001">If validation fails, then the endpoint MUST disable ECN.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P4P2P2-0004">Upon successful validation, an endpoint MAY continue to set an ECT codepoint in subsequent packets it sends, with the expectation that the path is ECN capable.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S13P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateAcknowledgedEcnCounts_AcceptsMatchingCountsForEachPacketNumberSpace()
    {
        QuicEcnValidationState state = new();

        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Initial, QuicEcnMarking.Ect0);
        state.RecordPacketSent(QuicPacketNumberSpace.Handshake, QuicEcnMarking.Ect1);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Initial,
            new QuicEcnCounts(2, 0, 0),
            newlyAcknowledgedEct0Packets: 2,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);

        Assert.True(state.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.Handshake,
            new QuicEcnCounts(0, 1, 0),
            newlyAcknowledgedEct0Packets: 0,
            newlyAcknowledgedEct1Packets: 1,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(state.IsEcnEnabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0002")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S13P4P2P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryValidateAcknowledgedEcnCounts_RejectsRepresentativeInvalidAckCountDeltas()
    {
        EcnValidationFuzzCase[] cases =
        [
            new(1, 0, null, 1, 0),
            new(0, 1, null, 0, 1),
            new(2, 0, new QuicEcnCounts(1, 0, 0), 2, 0),
            new(0, 2, new QuicEcnCounts(0, 1, 0), 0, 2),
            new(1, 0, new QuicEcnCounts(2, 0, 0), 1, 0),
            new(0, 1, new QuicEcnCounts(0, 2, 0), 0, 1),
            new(1, 0, new QuicEcnCounts(1, 1, 0), 1, 0),
            new(0, 1, new QuicEcnCounts(1, 1, 0), 0, 1),
        ];

        foreach (EcnValidationFuzzCase testCase in cases)
        {
            QuicEcnValidationState state = QuicEcnValidationTestSupport.CreateApplicationDataState(
                testCase.SentEct0Count,
                testCase.SentEct1Count);

            QuicEcnValidationTestSupport.AssertValidationFailure(
                state,
                testCase.ReportedCounts,
                testCase.NewlyAcknowledgedEct0Packets,
                testCase.NewlyAcknowledgedEct1Packets);
        }
    }

    private readonly record struct EcnValidationFuzzCase(
        ulong SentEct0Count,
        ulong SentEct1Count,
        QuicEcnCounts? ReportedCounts,
        ulong NewlyAcknowledgedEct0Packets,
        ulong NewlyAcknowledgedEct1Packets);
}
