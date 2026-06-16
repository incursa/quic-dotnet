// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Represents an Additional-section address record associated with a DNS service binding target.
/// </summary>
public sealed class DnsServiceBindingAdditionalAddress
{
    internal DnsServiceBindingAdditionalAddress(string ownerName, IPAddress address)
    {
        OwnerName = ownerName;
        Address = address;
    }

    /// <summary>
    /// Gets the owner name of the Additional-section address record.
    /// </summary>
    public string OwnerName { get; }

    /// <summary>
    /// Gets the parsed IPv4 or IPv6 address.
    /// </summary>
    public IPAddress Address { get; }
}
