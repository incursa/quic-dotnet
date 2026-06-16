// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Dns;

/// <summary>
/// Associates a parsed ServiceMode SVCB record with its owner name.
/// </summary>
public sealed class DnsServiceBindingNamedRecord
{
    private DnsServiceBindingNamedRecord(string ownerName, DnsServiceBindingWireRecord serviceRecord)
    {
        OwnerName = ownerName;
        ServiceRecord = serviceRecord;
    }

    /// <summary>
    /// Gets the owner name of the ServiceMode SVCB record.
    /// </summary>
    public string OwnerName { get; }

    /// <summary>
    /// Gets the parsed ServiceMode SVCB RDATA value.
    /// </summary>
    public DnsServiceBindingWireRecord ServiceRecord { get; }

    /// <summary>
    /// Creates a named ServiceMode SVCB record.
    /// </summary>
    public static DnsServiceBindingNamedRecord Create(string ownerName, DnsServiceBindingWireRecord serviceRecord)
    {
        ArgumentNullException.ThrowIfNull(serviceRecord);
        return new DnsServiceBindingNamedRecord(
            DnsServiceBindingAliasResolver.NormalizeResolutionName(ownerName, nameof(ownerName)),
            serviceRecord);
    }
}
