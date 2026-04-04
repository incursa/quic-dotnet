namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0011">Endpoints MUST advertise the number of active connection IDs they are willing to maintain using the active_connection_id_limit transport parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1P1-0011")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsActiveConnectionIdLimitForClients()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 8,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Equal(8UL, parsed.ActiveConnectionIdLimit);
        Assert.Null(parsed.InitialSourceConnectionId);
        Assert.Null(parsed.PreferredAddress);
    }
}
