namespace Incursa.Quic.Tests;

public sealed class QuicVersionNegotiationTests
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void Packet_GetSupportedVersion_RejectsNegativeIndex()
    {
        byte[] packetBytes = QuicHeaderTestData.BuildVersionNegotiation(
            0x4C,
            [0x01, 0x02],
            [0x03],
            0x11223344);

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(packetBytes, out QuicVersionNegotiationPacket packet));
        bool threw = false;
        try
        {
            _ = packet.GetSupportedVersion(-1);
        }
        catch (ArgumentOutOfRangeException)
        {
            threw = true;
        }

        Assert.True(threw);
    }
}
