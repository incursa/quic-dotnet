namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0021">For instance, a client MUST NOT send an ACK frame in a 0-RTT packet, because that can only acknowledge a 1-RTT packet.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P3-0021")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ZeroRttPingPayloadDoesNotParseAsAnAckFrame()
    {
        Assert.False(QuicFrameCodec.TryParseAckFrame(QuicS17P2P3TestSupport.CreatePingPayload(), out _, out _));
    }
}
