namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
public sealed class REQ_QUIC_RFC9000_S18P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_ServerCanSendOriginalDestinationConnectionId()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x10, 0x11],
        };

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, [0x10, 0x11]);
        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatTransportParameters_ClientCannotSendOriginalDestinationConnectionId()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x10, 0x11],
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            stackalloc byte[16],
            out int bytesWritten));
        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseTransportParameters_ServerRejectsOriginalDestinationConnectionIdFromPeer()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x00, [0x10, 0x11]);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }
}
