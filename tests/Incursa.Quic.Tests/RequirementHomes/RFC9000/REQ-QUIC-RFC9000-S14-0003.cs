namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S14-0003")]
public sealed class REQ_QUIC_RFC9000_S14_0003
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0003">The maximum datagram size MUST be defined as the largest size of UDP payload that can be sent across a network path using a single UDP datagram.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0004">QUIC MUST NOT be used if the network path cannot support a maximum datagram size of at least 1200 bytes.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6-0001">Clients that support multiple QUIC versions SHOULD ensure that the first UDP datagram they send is sized to the largest of the minimum datagram sizes from all versions they support, using PADDING frames as necessary.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6-0002">Clients that support multiple QUIC versions SHOULD ensure that the first UDP datagram they send is sized to the largest of the minimum datagram sizes from all versions they support, using PADDING frames (Section 19.1) as necessary.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S14-0003")]
    [Requirement("REQ-QUIC-RFC9000-S14-0004")]
    [Requirement("REQ-QUIC-RFC9000-S6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S6-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetRequiredInitialDatagramPayloadSize_UsesTheKnownMinimumForVersion1()
    {
        Assert.True(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize(
            [QuicVersionNegotiation.Version1],
            out int requiredPayloadSize));
        Assert.Equal(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, requiredPayloadSize);

        Assert.False(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize([], out _));
        Assert.False(QuicVersionNegotiation.TryGetRequiredInitialDatagramPayloadSize([0x0A0A0A0A], out _));
    }
}
