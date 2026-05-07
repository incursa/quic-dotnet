namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P4-0001">An endpoint MUST treat receipt of a transport parameter with an invalid value as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S7P4-0001")]
public sealed class REQ_QUIC_RFC9000_S7P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P4-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsAnInvalidActiveConnectionIdLimitValue()
    {
        byte[] invalidActiveConnectionIdLimit = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0E,
                QuicVarintTestData.EncodeMinimal(1)));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            invalidActiveConnectionIdLimit,
            QuicTransportParameterRole.Client,
            out _));
    }
}
