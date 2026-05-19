namespace Incursa.Quic;

internal enum QuicListenerPreAcceptanceDatagramAction
{
    Drop = 0,
    SendVersionNegotiation = 1,
    SendProtocolViolationClose = 2,
    AdmitInitial = 3,
    IssueRetryBootstrap = 4,
    BufferZeroRtt = 5,
}

internal static class QuicListenerPreAcceptanceIngressPolicy
{
    public static bool TrySliceFirstPacketForAdmission(
        ReadOnlyMemory<byte> datagram,
        out ReadOnlyMemory<byte> firstPacket)
    {
        firstPacket = default;

        if (!QuicPacketParser.TryGetPacketLength(datagram.Span, out int packetLength)
            || packetLength <= 0
            || packetLength > datagram.Length)
        {
            return false;
        }

        firstPacket = datagram[..packetLength];
        return true;
    }

    public static QuicListenerPreAcceptanceDatagramAction ClassifyUnroutedDatagram(
        ReadOnlySpan<byte> datagram,
        ReadOnlySpan<uint> supportedVersions,
        bool retryBootstrapEnabled,
        bool hasAlreadySentVersionNegotiation = false,
        int maximumBufferedZeroRttDatagramsPerConnection = 0)
    {
        if (!QuicPacketParser.TryParseLongHeader(datagram, out QuicLongHeaderPacket longHeader))
        {
            return QuicListenerPreAcceptanceDatagramAction.Drop;
        }

        if (QuicVersionNegotiation.ShouldSendVersionNegotiation(
            longHeader.Version,
            datagram.Length,
            supportedVersions,
            hasAlreadySentVersionNegotiation))
        {
            return QuicListenerPreAcceptanceDatagramAction.SendVersionNegotiation;
        }

        if (longHeader.Version != QuicVersionNegotiation.Version1)
        {
            return QuicListenerPreAcceptanceDatagramAction.Drop;
        }

        if (longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.Initial)
        {
            return datagram.Length < QuicVersionNegotiation.Version1MinimumDatagramPayloadSize
                ? QuicListenerPreAcceptanceDatagramAction.SendProtocolViolationClose
                : QuicListenerPreAcceptanceDatagramAction.AdmitInitial;
        }

        if (longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.ZeroRtt)
        {
            if (retryBootstrapEnabled)
            {
                return QuicListenerPreAcceptanceDatagramAction.IssueRetryBootstrap;
            }

            return maximumBufferedZeroRttDatagramsPerConnection > 0
                ? QuicListenerPreAcceptanceDatagramAction.BufferZeroRtt
                : QuicListenerPreAcceptanceDatagramAction.Drop;
        }

        return QuicListenerPreAcceptanceDatagramAction.Drop;
    }
}
