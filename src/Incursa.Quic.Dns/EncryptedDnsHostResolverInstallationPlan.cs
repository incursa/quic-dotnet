// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Deterministic host-resolver installation plan for encrypted DNS configuration.
/// </summary>
public sealed class EncryptedDnsHostResolverInstallationPlan
{
    internal EncryptedDnsHostResolverInstallationPlan(
        EncryptedDnsHostResolverInstallationStatus status,
        IReadOnlyList<EncryptedDnsSessionAttempt> encryptedSessionAttempts,
        IReadOnlyList<IPAddress> cleartextFallbackResolvers,
        IReadOnlyList<string> internalDnsDomains,
        bool splitTunnel)
    {
        Status = status;
        EncryptedSessionAttempts = new ReadOnlyCollection<EncryptedDnsSessionAttempt>([.. encryptedSessionAttempts]);
        CleartextFallbackResolvers = new ReadOnlyCollection<IPAddress>([.. cleartextFallbackResolvers]);
        InternalDnsDomains = new ReadOnlyCollection<string>([.. internalDnsDomains]);
        SplitTunnel = splitTunnel;
    }

    /// <summary>
    /// Gets the local installation readiness status.
    /// </summary>
    public EncryptedDnsHostResolverInstallationStatus Status { get; }

    /// <summary>
    /// Gets encrypted DNS session attempts to install into a platform resolver adapter.
    /// </summary>
    public IReadOnlyList<EncryptedDnsSessionAttempt> EncryptedSessionAttempts { get; }

    /// <summary>
    /// Gets cleartext resolvers that may be retained as failure fallback candidates.
    /// </summary>
    public IReadOnlyList<IPAddress> CleartextFallbackResolvers { get; }

    /// <summary>
    /// Gets internal DNS domains for split-tunnel scoped resolver installation.
    /// </summary>
    public IReadOnlyList<string> InternalDnsDomains { get; }

    /// <summary>
    /// Gets a value indicating whether the installation plan applies to a split-tunnel resolver scope.
    /// </summary>
    public bool SplitTunnel { get; }

    /// <summary>
    /// Gets a value indicating whether a platform adapter can install encrypted DNS resolver state.
    /// </summary>
    public bool CanInstallEncryptedResolver => Status == EncryptedDnsHostResolverInstallationStatus.Ready
        && EncryptedSessionAttempts.Count != 0;

    /// <summary>
    /// Gets a value indicating whether encrypted DNS applies to all resolver queries.
    /// </summary>
    public bool AppliesToAllDomains => CanInstallEncryptedResolver && !SplitTunnel;

    /// <summary>
    /// Gets a value indicating whether encrypted DNS applies only to internal split-tunnel domains.
    /// </summary>
    public bool AppliesToInternalDomainsOnly => CanInstallEncryptedResolver
        && SplitTunnel
        && InternalDnsDomains.Count != 0;

    /// <summary>
    /// Gets a value indicating whether applying the plan requires an operating-system resolver adapter.
    /// </summary>
    public bool RequiresPlatformResolverAdapter => CanInstallEncryptedResolver;
}
