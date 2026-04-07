namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18-0003")]
public sealed class REQ_QUIC_RFC9000_S18_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0003">Each transport parameter MUST be encoded as an (identifier, length, value) tuple, as shown in Figure 21:</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0004">The Transport Parameter ID field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0005">The Transport Parameter Length field MUST be encoded as a variable-length integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18-0006">The Transport Parameter Length field MUST contain the length of the Transport Parameter Value field in bytes.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18-0003")]
    [Requirement("REQ-QUIC-RFC9000-S18-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsTruncatedTupleValue()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25));
        byte[] truncated = tuple[..^1];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            truncated,
            QuicTransportParameterRole.Client,
            out _));
    }
}
