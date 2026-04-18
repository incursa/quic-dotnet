namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0018">The application-specific variant of CONNECTION_CLOSE (type 0x1d) MAY only be sent using 0-RTT or 1-RTT packets; see Section 12.5.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0018")]
public sealed class REQ_QUIC_RFC9000_S19P19_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_MapsApplicationConnectionCloseFramesToApplicationData()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(applicationPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(payload, out QuicConnectionCloseFrame parsedFrame, out int bytesConsumed));
        Assert.True(parsedFrame.IsApplicationError);
        Assert.Equal(payload.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketNumberSpace_DoesNotReclassifyHandshakePacketsAsApplicationDataWhenTheyCarryApplicationClosePayload()
    {
        QuicConnectionCloseFrame applicationFrame = new(0x1234, reasonPhrase: []);
        byte[] payload = QuicFrameTestData.BuildConnectionCloseFrame(applicationFrame);
        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(handshakePacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }
}
