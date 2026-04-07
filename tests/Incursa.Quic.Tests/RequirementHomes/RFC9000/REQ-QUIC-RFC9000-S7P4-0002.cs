namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4-0002")]
public sealed class REQ_QUIC_RFC9000_S7P4_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P4-0002">An endpoint MUST NOT send a parameter more than once in a given transport parameters extension.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P4-0003">An endpoint SHOULD treat receipt of duplicate transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S7P4-0002")]
    [Requirement("REQ-QUIC-RFC9000-S7P4-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsDuplicateTransportParameters()
    {
        byte[] duplicateKnownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(33)));

        byte[] duplicateUnknownParameter = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xAA]),
            QuicTransportParameterTestData.BuildTransportParameterTuple(27, [0xBB]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateKnownParameter,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            duplicateUnknownParameter,
            QuicTransportParameterRole.Client,
            out _));
    }
}
