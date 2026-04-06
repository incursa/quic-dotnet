namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0007">In either role, an application protocol MAY configure minimum values for the initial number of permitted streams of each type as communicated in the transport parameters.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P3-0007")]
public sealed class REQ_QUIC_RFC9000_S5P3_0007
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0007">In either role, an application protocol MAY configure minimum values for the initial number of permitted streams of each type as communicated in the transport parameters.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P3-0007")]
    public void TryFormatTransportParameters_AllowsConfiguringInitialStreamCountsForEitherRole(bool senderIsClient)
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = 4,
            InitialMaxStreamsUni = 3,
        };

        QuicTransportParameterRole senderRole = senderIsClient
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;
        QuicTransportParameterRole receiverRole = senderIsClient
            ? QuicTransportParameterRole.Server
            : QuicTransportParameterRole.Client;

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x08, QuicVarintTestData.EncodeMinimal(4)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x09, QuicVarintTestData.EncodeMinimal(3)));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            receiverRole,
            out QuicTransportParameters parsed));

        Assert.Equal(4UL, parsed.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsed.InitialMaxStreamsUni);
    }
}
