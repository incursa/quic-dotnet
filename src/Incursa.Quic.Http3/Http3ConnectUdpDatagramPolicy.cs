// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 UDP proxying HTTP Datagram receive and discard policy.
/// </summary>
public static class Http3ConnectUdpDatagramPolicy
{
    /// <summary>
    /// Classifies how an endpoint handles an unknown Context ID.
    /// </summary>
    public static Http3ConnectUdpUnknownContextAction ClassifyUnknownContextId(bool temporaryBufferAvailable)
    {
        return temporaryBufferAvailable
            ? Http3ConnectUdpUnknownContextAction.BufferTemporarily
            : Http3ConnectUdpUnknownContextAction.DropSilently;
    }

    /// <summary>
    /// Returns true when a UDP payload exceeds a known outgoing UDP packet limit.
    /// </summary>
    public static bool ShouldDiscardForKnownOutgoingLimit(int udpPayloadLength, int outgoingUdpPacketLimit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(udpPayloadLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(outgoingUdpPacketLimit);
        return udpPayloadLength > outgoingUdpPacketLimit;
    }

    /// <summary>
    /// Returns true when a DATAGRAM capsule carrying a discarded datagram should be discarded without buffering.
    /// </summary>
    public static bool ShouldDiscardDatagramCapsuleWhenDatagramDiscarded(bool transportedByDatagramCapsule)
    {
        return transportedByDatagramCapsule;
    }

    /// <summary>
    /// Returns true when a future extension uses header fields or capsules to register Context IDs.
    /// </summary>
    public static bool CanUseFutureContextRegistrationMechanism(bool usesHeaderField, bool usesCapsule)
    {
        return usesHeaderField || usesCapsule;
    }

    /// <summary>
    /// Returns true when a UDP proxy can send the payload without introducing IP fragmentation.
    /// </summary>
    public static bool CanForwardWithoutIpFragmentation(int udpPayloadLength, int outgoingUdpPacketLimit)
    {
        return !ShouldDiscardForKnownOutgoingLimit(udpPayloadLength, outgoingUdpPacketLimit);
    }
}
