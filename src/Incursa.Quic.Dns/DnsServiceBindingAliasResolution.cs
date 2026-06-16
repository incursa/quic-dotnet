// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Describes the outcome of DNS service binding AliasMode chain resolution.
/// </summary>
public sealed class DnsServiceBindingAliasResolution
{
    internal DnsServiceBindingAliasResolution(
        DnsServiceBindingAliasResolutionStatus status,
        string queryName,
        string resolvedName,
        IReadOnlyList<string> aliasChain,
        IReadOnlyList<DnsServiceBindingNamedRecord> serviceRecords)
    {
        Status = status;
        QueryName = queryName;
        ResolvedName = resolvedName;
        AliasChain = new ReadOnlyCollection<string>([.. aliasChain]);
        ServiceRecords = new ReadOnlyCollection<DnsServiceBindingNamedRecord>([.. serviceRecords]);
    }

    /// <summary>
    /// Gets the resolution status.
    /// </summary>
    public DnsServiceBindingAliasResolutionStatus Status { get; }

    /// <summary>
    /// Gets the normalized query name where resolution started.
    /// </summary>
    public string QueryName { get; }

    /// <summary>
    /// Gets the final normalized name inspected by the resolver.
    /// </summary>
    public string ResolvedName { get; }

    /// <summary>
    /// Gets the ordered owner names traversed before the final resolved name.
    /// </summary>
    public IReadOnlyList<string> AliasChain { get; }

    /// <summary>
    /// Gets the ServiceMode records found at the resolved name.
    /// </summary>
    public IReadOnlyList<DnsServiceBindingNamedRecord> ServiceRecords { get; }

    /// <summary>
    /// Gets a value indicating whether resolution found one or more ServiceMode records.
    /// </summary>
    public bool Succeeded => Status == DnsServiceBindingAliasResolutionStatus.Succeeded;
}
