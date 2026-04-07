namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0037")]
public sealed class REQ_QUIC_RFC9000_S18P2_0037
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0001">This transport parameter MUST only be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0004">This transport parameter MAY be sent by a server.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0005">This transport parameter MUST NOT be sent by a client.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0037">A client MUST NOT include any server-only transport parameter: original_destination_connection_id, preferred_address, retry_source_connection_id, or stateless_reset_token.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0001")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatTransportParameters_RejectsServerOnlyParametersWhenSendingAsClient()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = [0x01, 0x02],
            StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x30 + value)).ToArray(),
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [192, 0, 2, 1],
                IPv4Port = 443,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = [0xAA],
                StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x40 + value)).ToArray(),
            },
            RetrySourceConnectionId = [0x10, 0x11],
        };

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            stackalloc byte[128],
            out _));
    }
}
