// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Tracks RFC 9298 CONNECT-UDP Context ID allocation inside one HTTP request namespace.
/// </summary>
public sealed class Http3ConnectUdpContextIdRegistry
{
    private readonly HashSet<ulong> allocatedContextIds = [];

    /// <summary>
    /// Registers a dynamically allocated non-zero client Context ID.
    /// </summary>
    public void AllocateClientContextId(ulong contextId)
    {
        ValidateDynamicContextId(contextId);
        if ((contextId & 1UL) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "Client-allocated CONNECT-UDP Context IDs must be even.");
        }

        Add(contextId);
    }

    /// <summary>
    /// Registers a dynamically allocated non-zero proxy Context ID.
    /// </summary>
    public void AllocateProxyContextId(ulong contextId)
    {
        ValidateDynamicContextId(contextId);
        if ((contextId & 1UL) == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "Proxy-allocated CONNECT-UDP Context IDs must be odd.");
        }

        Add(contextId);
    }

    /// <summary>
    /// Returns true when the Context ID is reserved or has been allocated in this request namespace.
    /// </summary>
    public bool IsUsable(ulong contextId)
    {
        return contextId == Http3ConnectUdpDatagram.UdpPayloadContextId || allocatedContextIds.Contains(contextId);
    }

    /// <summary>
    /// Returns the allocated non-zero Context IDs in this request namespace.
    /// </summary>
    public IReadOnlyCollection<ulong> AllocatedContextIds => allocatedContextIds;

    private static void ValidateDynamicContextId(ulong contextId)
    {
        if (contextId == Http3ConnectUdpDatagram.UdpPayloadContextId)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "CONNECT-UDP Context ID zero is reserved for UDP payloads.");
        }

        if (contextId > Http3ConnectUdpDatagram.MaximumContextId)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "CONNECT-UDP Context IDs are 62-bit integers.");
        }
    }

    private void Add(ulong contextId)
    {
        if (!allocatedContextIds.Add(contextId))
        {
            throw new InvalidOperationException("CONNECT-UDP Context IDs must not be re-allocated inside one request namespace.");
        }
    }
}
