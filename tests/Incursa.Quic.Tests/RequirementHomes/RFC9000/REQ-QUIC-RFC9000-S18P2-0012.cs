namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0012">Setting this parameter MUST be equivalent to sending a MAX_STREAMS (Section 19.11) of the corresponding type with the same value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S18P2-0012")]
public sealed class REQ_QUIC_RFC9000_S18P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0012">Setting this parameter MUST be equivalent to sending a MAX_STREAMS (Section 19.11) of the corresponding type with the same value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0012")]
    public void TryFormatTransportParameters_EmitsInitialMaxStreamsTuples()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 3,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x08, QuicVarintTestData.EncodeMinimal(4)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x09, QuicVarintTestData.EncodeMinimal(3)));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(4UL, parsed.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsed.InitialMaxStreamsUni);
    }
}
