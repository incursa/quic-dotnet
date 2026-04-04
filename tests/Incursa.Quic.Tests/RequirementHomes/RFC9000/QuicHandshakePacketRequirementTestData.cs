namespace Incursa.Quic.Tests;

internal static class QuicHandshakePacketRequirementTestData
{
    public static byte BuildHandshakeHeaderControlBits(int packetNumberLength = 2, byte reservedBits = 0x02)
    {
        Assert.InRange(packetNumberLength, 1, 4);
        Assert.InRange((int)reservedBits, 0, 3);

        return (byte)(0x60 | ((reservedBits & 0x03) << 2) | ((packetNumberLength - 1) & 0x03));
    }

    public static byte[] BuildHandshakeVersionSpecificData(int packetNumberLength, byte[]? protectedPayload = null)
    {
        return QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            CreatePacketNumber(packetNumberLength),
            protectedPayload ?? [0xAA]);
    }

    public static byte[] BuildHandshakePacket(
        int packetNumberLength = 2,
        byte reservedBits = 0x02,
        uint version = 1,
        byte[]? destinationConnectionId = null,
        byte[]? sourceConnectionId = null,
        byte[]? protectedPayload = null)
    {
        return QuicHeaderTestData.BuildLongHeader(
            BuildHandshakeHeaderControlBits(packetNumberLength, reservedBits),
            version,
            destinationConnectionId ?? [0x10, 0x11],
            sourceConnectionId ?? [0x20],
            BuildHandshakeVersionSpecificData(packetNumberLength, protectedPayload));
    }

    public static byte[] CreatePacketNumber(int packetNumberLength)
    {
        return Enumerable.Range(0, packetNumberLength)
            .Select(index => (byte)(index + 1))
            .ToArray();
    }
}
