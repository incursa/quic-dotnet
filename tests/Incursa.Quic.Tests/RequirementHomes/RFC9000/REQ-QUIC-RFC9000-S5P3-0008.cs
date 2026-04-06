namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0008">In either role, an application protocol MAY control resource allocation for receive buffers by setting flow control limits both for streams and for the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P3-0008")]
public sealed class REQ_QUIC_RFC9000_S5P3_0008
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P3-0008">In either role, an application protocol MAY control resource allocation for receive buffers by setting flow control limits both for streams and for the connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P3-0008")]
    public void TryFormatTransportParameters_AllowsConfiguringFlowControlLimitsForEitherRole(bool senderIsClient)
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 4096,
            InitialMaxStreamDataBidiLocal = 1024,
            InitialMaxStreamDataBidiRemote = 2048,
            InitialMaxStreamDataUni = 512,
        };

        QuicTransportParameterRole senderRole = senderIsClient
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;
        QuicTransportParameterRole receiverRole = senderIsClient
            ? QuicTransportParameterRole.Server
            : QuicTransportParameterRole.Client;

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x04, QuicVarintTestData.EncodeMinimal(4096)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x05, QuicVarintTestData.EncodeMinimal(1024)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x06, QuicVarintTestData.EncodeMinimal(2048)),
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x07, QuicVarintTestData.EncodeMinimal(512)));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            receiverRole,
            out QuicTransportParameters parsed));

        Assert.Equal(4096UL, parsed.InitialMaxData);
        Assert.Equal(1024UL, parsed.InitialMaxStreamDataBidiLocal);
        Assert.Equal(2048UL, parsed.InitialMaxStreamDataBidiRemote);
        Assert.Equal(512UL, parsed.InitialMaxStreamDataUni);
    }
}
