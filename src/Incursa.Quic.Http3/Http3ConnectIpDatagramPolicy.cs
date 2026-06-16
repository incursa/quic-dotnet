// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 IP proxying HTTP Datagram policy helpers.
/// </summary>
public static class Http3ConnectIpDatagramPolicy
{
    /// <summary>
    /// Classifies how an endpoint handles an unknown Context ID.
    /// </summary>
    public static Http3ConnectIpUnknownContextAction ClassifyUnknownContextId(bool temporaryBufferAvailable)
    {
        return temporaryBufferAvailable
            ? Http3ConnectIpUnknownContextAction.BufferTemporarily
            : Http3ConnectIpUnknownContextAction.DropSilently;
    }

    /// <summary>
    /// Returns true when a future extension uses header fields or capsules to register Context IDs.
    /// </summary>
    public static bool CanUseFutureContextRegistrationMechanism(bool usesHeaderField, bool usesCapsule)
    {
        return usesHeaderField || usesCapsule;
    }

    /// <summary>
    /// Returns true when payload semantics are defined for the supplied Context ID.
    /// </summary>
    public static bool PayloadSemanticsDependOnContextId(ulong contextId, bool contextIdRegistered)
    {
        return contextId == Http3ConnectIpDatagram.IpPayloadContextId || contextIdRegistered;
    }

    /// <summary>
    /// Returns true when a client may optimistically send proxied IP packets before a response.
    /// </summary>
    public static bool CanClientOptimisticallySendIpPackets(bool usingHttp2, bool usingHttp3)
    {
        return usingHttp2 || usingHttp3;
    }
}
