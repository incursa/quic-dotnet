// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Packet-number expansion uses the RFC 9000 half-window rule, so the arithmetic here
// must stay aligned with the expected-packet window rather than being simplified to a nearest fit.
// SEE: ExpandTruncatedPacketNumber
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
