namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0001")]
public sealed class REQ_QUIC_RFC9000_S5P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IncomingPacketsAreClassifiedOnReceiptByHeaderForm()
    {
        byte[] longHeaderDatagram = QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        byte[] shortHeaderDatagram = QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(longHeaderDatagram, out QuicHeaderForm longHeaderForm));
        Assert.Equal(QuicHeaderForm.Long, longHeaderForm);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(shortHeaderDatagram, out QuicHeaderForm shortHeaderForm));
        Assert.Equal(QuicHeaderForm.Short, shortHeaderForm);
    }
}
