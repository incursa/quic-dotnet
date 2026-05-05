namespace Incursa.Quic;

internal enum QuicListenerPreAcceptanceDatagramAction
{
    Drop = 0,
    SendVersionNegotiation = 1,
    SendProtocolViolationClose = 2,
    AdmitInitial = 3,
    IssueRetryBootstrap = 4,
}

internal static class QuicListenerPreAcceptanceIngressPolicy
{
    public static QuicListenerPreAcceptanceDatagramAction ClassifyUnroutedDatagram(
        ReadOnlySpan<byte> datagram,
        ReadOnlySpan<uint> supportedVersions,
        bool retryBootstrapEnabled,
        bool hasAlreadySentVersionNegotiation = false)
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

        if (retryBootstrapEnabled && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.ZeroRtt)
        {
            return QuicListenerPreAcceptanceDatagramAction.IssueRetryBootstrap;
        }

        return QuicListenerPreAcceptanceDatagramAction.Drop;
    }
}
