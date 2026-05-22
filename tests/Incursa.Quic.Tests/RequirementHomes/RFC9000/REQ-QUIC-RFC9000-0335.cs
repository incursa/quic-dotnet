namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0335")]
public sealed class REQ_QUIC_RFC9000_0335
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0334">An endpoint MUST treat receipt of a transport parameter with an invalid value as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0335">An endpoint MUST NOT send a parameter more than once in a given transport parameters extension.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0336">An endpoint SHOULD treat receipt of duplicate transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0334")]
    [Requirement("REQ-QUIC-RFC9000-0335")]
    [Requirement("REQ-QUIC-RFC9000-0336")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_UsesEachParameterOnceAndParsesBack()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 25,
            DisableActiveMigration = true,
            ActiveConnectionIdLimit = 2,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x01, QuicVarintTestData.EncodeMinimal(25)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0C, []),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x0E, QuicVarintTestData.EncodeMinimal(2)));

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.Equal(25UL, parsed.MaxIdleTimeout);
        Assert.True(parsed.DisableActiveMigration);
        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0335">An endpoint MUST NOT send a parameter more than once in a given transport parameters extension.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0336">An endpoint SHOULD treat receipt of duplicate transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0335")]
    [Requirement("REQ-QUIC-RFC9000-0336")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
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
