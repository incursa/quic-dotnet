namespace Incursa.Quic;

internal static class QuicPacketNumberEncoding
{
    private const int BitsPerByte = 8;

    internal static ulong ExpandTruncatedPacketNumber(
        ulong truncatedPacketNumber,
        int packetNumberLength,
        ulong expectedPacketNumber)
    {
        int packetNumberBits = checked(packetNumberLength * BitsPerByte);
        ulong packetNumberWindow = 1UL << packetNumberBits;
        ulong packetNumberHalfWindow = packetNumberWindow / 2;
        ulong packetNumberMask = packetNumberWindow - 1;
        ulong candidatePacketNumber = (expectedPacketNumber & ~packetNumberMask) | truncatedPacketNumber;

        if (candidatePacketNumber + packetNumberHalfWindow <= expectedPacketNumber
            && candidatePacketNumber <= ulong.MaxValue - packetNumberWindow)
        {
            candidatePacketNumber += packetNumberWindow;
        }
        else if (candidatePacketNumber > expectedPacketNumber + packetNumberHalfWindow
            && candidatePacketNumber >= packetNumberWindow)
        {
            candidatePacketNumber -= packetNumberWindow;
        }

        return candidatePacketNumber;
    }
}
