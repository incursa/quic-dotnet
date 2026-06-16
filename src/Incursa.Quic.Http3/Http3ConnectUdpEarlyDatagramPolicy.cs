// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9298 policy for early CONNECT-UDP HTTP Datagrams.
/// </summary>
public static class Http3ConnectUdpEarlyDatagramPolicy
{
    /// <summary>
    /// Indicates that clients can optimistically send HTTP Datagrams before receiving the response.
    /// </summary>
    public const bool ClientMaySendOptimisticDatagramsBeforeResponse = true;

    /// <summary>
    /// Classifies an HTTP Datagram that might have arrived before its corresponding request.
    /// </summary>
    public static Http3ConnectUdpEarlyDatagramAction ClassifyEarlyDatagram(
        bool correspondingRequestKnown,
        bool temporaryBufferAvailable)
    {
        if (correspondingRequestKnown)
        {
            return Http3ConnectUdpEarlyDatagramAction.Process;
        }

        return temporaryBufferAvailable
            ? Http3ConnectUdpEarlyDatagramAction.BufferTemporarily
            : Http3ConnectUdpEarlyDatagramAction.DropSilently;
    }

    /// <summary>
    /// Returns true when a receiver that buffers early datagrams must apply buffering limits.
    /// </summary>
    public static bool ShouldApplyBufferingLimits(bool bufferingEarlyDatagrams)
    {
        return bufferingEarlyDatagrams;
    }
}
