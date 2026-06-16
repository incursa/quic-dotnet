// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9484 CONNECT-IP Requested Address entry.
/// </summary>
public sealed class Http3ConnectIpRequestedAddress
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectIpRequestedAddress" /> class.
    /// </summary>
    public Http3ConnectIpRequestedAddress(ulong requestId, IPAddress address, int prefixLength)
    {
        if (requestId == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(requestId), "CONNECT-IP ADDRESS_REQUEST Request ID must not be zero.");
        }

        AssignedShape = new Http3ConnectIpAssignedAddress(requestId, address, prefixLength);
    }

    /// <summary>
    /// Gets the non-zero request ID.
    /// </summary>
    public ulong RequestId => AssignedShape.RequestId;

    /// <summary>
    /// Gets the requested IP address or prefix.
    /// </summary>
    public IPAddress Address => AssignedShape.Address;

    /// <summary>
    /// Gets the requested IP version.
    /// </summary>
    public int IpVersion => AssignedShape.IpVersion;

    /// <summary>
    /// Gets the requested IP prefix length.
    /// </summary>
    public int PrefixLength => AssignedShape.PrefixLength;

    internal Http3ConnectIpAssignedAddress AssignedShape { get; }
}
