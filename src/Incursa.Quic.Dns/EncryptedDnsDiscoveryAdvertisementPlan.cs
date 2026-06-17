// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;

namespace Incursa.Quic.Dns;

/// <summary>
/// Deterministic adapter-neutral advertisement plan for RFC 9463 encrypted DNS discovery.
/// </summary>
public sealed class EncryptedDnsDiscoveryAdvertisementPlan
{
    internal EncryptedDnsDiscoveryAdvertisementPlan(
        EncryptedDnsDiscoveryAdvertisementStatus status,
        EncryptedDnsDiscoveryDhcpv4Option? dhcpv4Option,
        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> dhcpv6Options,
        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> routerAdvertisementOptions,
        bool adnOnly)
    {
        Status = status;
        Dhcpv4Option = dhcpv4Option;
        Dhcpv6Options = new ReadOnlyCollection<EncryptedDnsDiscoveryDhcpv6Option>([.. dhcpv6Options]);
        RouterAdvertisementOptions = new ReadOnlyCollection<EncryptedDnsDiscoveryNeighborDiscoveryOption>([.. routerAdvertisementOptions]);
        AdnOnly = adnOnly;
    }

    /// <summary>
    /// Gets the local advertisement planning status.
    /// </summary>
    public EncryptedDnsDiscoveryAdvertisementStatus Status { get; }

    /// <summary>
    /// Gets the DHCPv4 OPTION_V4_DNR payload to publish, when requested and applicable.
    /// </summary>
    public EncryptedDnsDiscoveryDhcpv4Option? Dhcpv4Option { get; }

    /// <summary>
    /// Gets DHCPv6 OPTION_V6_DNR payloads to publish.
    /// </summary>
    public IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> Dhcpv6Options { get; }

    /// <summary>
    /// Gets Neighbor Discovery encrypted DNS options to publish in Router Advertisements.
    /// </summary>
    public IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> RouterAdvertisementOptions { get; }

    /// <summary>
    /// Gets a value indicating whether the plan publishes ADN-only discovery information.
    /// </summary>
    public bool AdnOnly { get; }

    /// <summary>
    /// Gets a value indicating whether the plan includes DHCPv4 advertisement payloads.
    /// </summary>
    public bool PublishesDhcpv4 => Dhcpv4Option is not null;

    /// <summary>
    /// Gets a value indicating whether the plan includes DHCPv6 advertisement payloads.
    /// </summary>
    public bool PublishesDhcpv6 => Dhcpv6Options.Count != 0;

    /// <summary>
    /// Gets a value indicating whether the plan includes Router Advertisement payloads.
    /// </summary>
    public bool PublishesRouterAdvertisements => RouterAdvertisementOptions.Count != 0;

    /// <summary>
    /// Gets a value indicating whether applying this plan requires a platform advertisement adapter.
    /// </summary>
    public bool RequiresPlatformAdvertisementAdapter => Status == EncryptedDnsDiscoveryAdvertisementStatus.Ready
        && (PublishesDhcpv4 || PublishesDhcpv6 || PublishesRouterAdvertisements);
}
