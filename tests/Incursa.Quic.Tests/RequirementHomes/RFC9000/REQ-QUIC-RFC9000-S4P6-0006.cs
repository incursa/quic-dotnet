namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
public sealed class REQ_QUIC_RFC9000_S4P6_0006
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P6-0006">If an oversized max_streams value is received in a transport parameter, the connection MUST be closed immediately with TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S4P6-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatAndParseTransportParameters_RejectsInitialMaxStreamsAboveTheLimit()
    {
        QuicTransportParameters boundaryParameters = new()
        {
            InitialMaxStreamsBidi = 1UL << 60,
            InitialMaxStreamsUni = 1UL << 60,
        };

        Span<byte> boundaryDestination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            boundaryParameters,
            QuicTransportParameterRole.Server,
            boundaryDestination,
            out int boundaryBytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            boundaryDestination[..boundaryBytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters boundaryParsed));
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsBidi);
        Assert.Equal(1UL << 60, boundaryParsed.InitialMaxStreamsUni);

        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = (1UL << 60) + 1,
            InitialMaxStreamsUni = (1UL << 60) + 1,
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            stackalloc byte[64],
            out _));

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x08,
            QuicVarintTestData.EncodeMinimal((1UL << 60) + 1));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Client,
            out _));
    }
}
