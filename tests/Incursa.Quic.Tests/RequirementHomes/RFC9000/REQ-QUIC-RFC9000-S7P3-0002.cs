namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0002">Each endpoint MUST include the value of the Source Connection ID field from the first Initial packet it sent in the initial_source_connection_id transport parameter.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S7P3-0002")]
public sealed class REQ_QUIC_RFC9000_S7P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsInitialSourceConnectionId()
    {
        QuicTransportParameters parameters = new()
        {
            InitialSourceConnectionId = [0x11, 0x22],
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

        Assert.True(parameters.InitialSourceConnectionId!.AsSpan().SequenceEqual(parsed.InitialSourceConnectionId!));
        Assert.Null(parsed.ActiveConnectionIdLimit);
    }
}
