namespace Incursa.Quic.Tests;

internal static class QuicRetryPacketRequirementTestData
{
    public static byte[] BuildRetryPacket(
        byte[]? destinationConnectionId = null,
        byte[]? sourceConnectionId = null,
        byte[]? retryToken = null,
        byte[]? retryIntegrityTag = null,
        uint version = 1,
        byte unusedBits = 0x00)
    {
        retryToken ??= [];
        retryIntegrityTag ??= new byte[16];

        byte[] versionSpecificData = new byte[retryToken.Length + retryIntegrityTag.Length];
        retryToken.CopyTo(versionSpecificData, 0);
        retryIntegrityTag.CopyTo(versionSpecificData, retryToken.Length);

        return QuicHeaderTestData.BuildLongHeader(
            BuildRetryHeaderControlBits(version, unusedBits),
            version,
            destinationConnectionId ?? [0x10],
            sourceConnectionId ?? [0x20],
            versionSpecificData);
    }

    public static byte BuildRetryHeaderControlBits(byte unusedBits = 0x00)
        => BuildRetryHeaderControlBits(QuicVersionNegotiation.Version1, unusedBits);

    public static byte BuildRetryHeaderControlBits(uint version, byte unusedBits = 0x00)
    {
        return (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (QuicVersionNegotiation.GetLongHeaderPacketTypeBits(version, QuicLongPacketType.Retry) << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | (unusedBits & QuicPacketHeaderBits.TypeSpecificBitsMask));
    }
}
