// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Tracks RFC 9484 CONNECT-IP Context ID allocation inside one HTTP request namespace.
/// </summary>
public sealed class Http3ConnectIpContextIdRegistry
{
    private readonly HashSet<ulong> allocatedContextIds = [];

    /// <summary>
    /// Registers a dynamically allocated non-zero Context ID.
    /// </summary>
    public void AllocateContextId(ulong contextId)
    {
        ValidateDynamicContextId(contextId);
        if (!allocatedContextIds.Add(contextId))
        {
            throw new InvalidOperationException("CONNECT-IP Context IDs must not be re-allocated inside one request namespace.");
        }
    }

    /// <summary>
    /// Returns true when the Context ID is reserved or has been allocated in this request namespace.
    /// </summary>
    public bool IsUsable(ulong contextId)
    {
        return contextId == Http3ConnectIpDatagram.IpPayloadContextId || allocatedContextIds.Contains(contextId);
    }

    /// <summary>
    /// Returns the allocated non-zero Context IDs in this request namespace.
    /// </summary>
    public IReadOnlyCollection<ulong> AllocatedContextIds => allocatedContextIds;

    private static void ValidateDynamicContextId(ulong contextId)
    {
        if (contextId == Http3ConnectIpDatagram.IpPayloadContextId)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "CONNECT-IP Context ID zero is reserved for IP packets.");
        }

        if (contextId > Http3ConnectIpDatagram.MaximumContextId)
        {
            throw new ArgumentOutOfRangeException(nameof(contextId), "CONNECT-IP Context IDs are 62-bit integers.");
        }
    }
}
