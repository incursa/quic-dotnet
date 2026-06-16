// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 forwarding, congestion, QUIC DATAGRAM, and ECN policy helpers.
/// </summary>
public static class Http3ConnectUdpForwardingPolicy
{
    /// <summary>
    /// Indicates that UDP proxies should avoid increasing UDP burstiness.
    /// </summary>
    public const bool AvoidIncreasingBurstiness = true;

    /// <summary>
    /// Indicates whether UDP proxies can queue packets only to increase batching.
    /// </summary>
    public const bool QueuePacketsToIncreaseBatchingAllowed = false;

    /// <summary>
    /// Returns true only when out-of-band information proves the inner traffic is congestion-controlled.
    /// </summary>
    public static bool CanDisableCongestionControl(bool innerTrafficKnownCongestionControlledWithCertainty)
    {
        return innerTrafficKnownCongestionControlledWithCertainty;
    }

    /// <summary>
    /// Indicates whether ECN support can be signaled when congestion control is disabled.
    /// </summary>
    public const bool EcnSupportSignalAllowedWhenCongestionControlDisabled = false;

    /// <summary>
    /// Gets the IP ECN codepoint to use when congestion control is disabled.
    /// </summary>
    public const Http3ConnectUdpEcnCodepoint EcnCodepointWhenCongestionControlDisabled = Http3ConnectUdpEcnCodepoint.NotEct;

    /// <summary>
    /// Returns true when ECN feedback can still be reported to a peer that may not have disabled congestion control.
    /// </summary>
    public static bool CanContinueReportingEcnFeedback(bool peerMayNotHaveDisabledCongestionControl)
    {
        return peerMayNotHaveDisabledCongestionControl;
    }

    /// <summary>
    /// Indicates that HTTP/3 is preferred for UDP proxying.
    /// </summary>
    public const bool PreferHttp3ForUdpProxying = true;

    /// <summary>
    /// Returns true when HTTP/3 and QUIC DATAGRAM are available for UDP payloads.
    /// </summary>
    public static bool ShouldTransmitUdpPayloadsInQuicDatagramFrames(bool usingHttp3, bool quicDatagramEnabled)
    {
        return usingHttp3 && quicDatagramEnabled;
    }

    /// <summary>
    /// Returns true when a UDP payload fits the QUIC DATAGRAM payload limit.
    /// </summary>
    public static bool CanFitInQuicDatagram(int udpPayloadLength, int quicDatagramPayloadLimit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(udpPayloadLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(quicDatagramPayloadLimit);
        return udpPayloadLength <= quicDatagramPayloadLimit;
    }

    /// <summary>
    /// Indicates whether oversized UDP payloads should be sent in DATAGRAM capsules when QUIC DATAGRAM is in use.
    /// </summary>
    public const bool OversizedPayloadDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse = false;

    /// <summary>
    /// Returns true when a UDP payload is too large for the QUIC DATAGRAM path.
    /// </summary>
    public static bool ShouldDropOversizedUdpPayload(int udpPayloadLength, int quicDatagramPayloadLimit)
    {
        return !CanFitInQuicDatagram(udpPayloadLength, quicDatagramPayloadLimit);
    }

    /// <summary>
    /// Returns true when an ICMP Packet Too Big message should be sent for an oversized target payload.
    /// </summary>
    public static bool ShouldSendIcmpPacketTooBigForOversizedTargetPayload(int udpPayloadLength, int quicDatagramPayloadLimit)
    {
        return !CanFitInQuicDatagram(udpPayloadLength, quicDatagramPayloadLimit);
    }

    /// <summary>
    /// Indicates whether UDP proxying tunnels include an inner IP header.
    /// </summary>
    public const bool TunnelIncludesInnerIpHeader = false;

    /// <summary>
    /// Indicates whether clients can control the proxy's UDP ECN codepoints.
    /// </summary>
    public const bool ClientControlOutboundUdpEcnCodepointsAllowed = false;

    /// <summary>
    /// Indicates whether UDP proxies can communicate per-packet target markings to clients.
    /// </summary>
    public const bool CommunicatePerPacketTargetMarkingsToClientAllowed = false;

    /// <summary>
    /// Indicates that target ECN bits are ignored by the UDP proxy.
    /// </summary>
    public const bool IgnoreTargetEcnBits = true;

    /// <summary>
    /// Gets the ECN codepoint a UDP proxy uses for outbound UDP packets to the target.
    /// </summary>
    public const Http3ConnectUdpEcnCodepoint OutboundUdpEcnCodepoint = Http3ConnectUdpEcnCodepoint.NotEct;
}
