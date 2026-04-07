namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0038")]
public sealed class REQ_QUIC_RFC9000_S18P2_0038
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0038">A server MUST treat receipt of any of these transport parameters as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsServerOnlyParametersWhenReceivingAsServer()
    {
        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, Enumerable.Range(0, 16).Select(value => (byte)(0x50 + value)).ToArray());

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            tuple,
            QuicTransportParameterRole.Server,
            out _));
    }
}
