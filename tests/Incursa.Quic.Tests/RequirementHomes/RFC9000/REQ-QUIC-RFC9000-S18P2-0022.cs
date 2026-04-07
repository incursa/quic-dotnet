namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0022")]
public sealed class REQ_QUIC_RFC9000_S18P2_0022
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0019">The server&apos;s preferred address MUST be used to effect a change in server address at the end of the handshake, as described in Section 9.6.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0020">Servers MAY choose to only send a preferred address of one address family by sending an all-zero address and port (0.0.0.0:0 or [::]:0) for the other family.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0021">IP addresses MUST be encoded in network byte order.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0022">The preferred_address transport parameter MUST contain an address and port for both IPv4 and IPv6.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0023">Finally, a 16-byte Stateless Reset Token field MUST include the stateless reset token associated with the connection ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0028">The IPv4 Address field MUST be 32 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0029">The IPv4 Port field MUST be 16 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0030">The IPv6 Address field MUST be 128 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0031">The IPv6 Port field MUST be 16 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0032">The Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0033">The Stateless Reset Token field MUST be 128 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0019")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0020")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0021")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0022")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0023")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0031")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0032")]
    [Requirement("REQ-QUIC-RFC9000-S18P2-0033")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsTruncatedPreferredAddressValue()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [0xAA, 0xBB],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0x70 + value)).ToArray());

        byte[] tuple = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);
        byte[] truncated = tuple[..^1];

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            truncated,
            QuicTransportParameterRole.Client,
            out _));
    }
}
