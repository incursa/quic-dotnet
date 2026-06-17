// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Dns;

/// <summary>
/// Builds side-effect-free DHCP and Router Advertisement payload plans for RFC 9463 encrypted DNS discovery.
/// </summary>
public static class EncryptedDnsDiscoveryAdvertisementPlanner
{
    /// <summary>
    /// Creates an adapter-neutral advertisement plan for a router or forwarder.
    /// </summary>
    public static EncryptedDnsDiscoveryAdvertisementPlan CreatePlan(
        string authenticationDomainName,
        IEnumerable<IPAddress>? lanFacingAddresses,
        ushort servicePriority = 0,
        uint lifetime = EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime,
        IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters = null,
        bool publishDhcpv4 = true,
        bool publishDhcpv6 = true,
        bool publishRouterAdvertisements = true,
        bool adnOnly = false)
    {
        if (!publishDhcpv4 && !publishDhcpv6 && !publishRouterAdvertisements)
        {
            return new EncryptedDnsDiscoveryAdvertisementPlan(
                EncryptedDnsDiscoveryAdvertisementStatus.BlockedByPolicy,
                dhcpv4Option: null,
                dhcpv6Options: [],
                routerAdvertisementOptions: [],
                adnOnly);
        }

        IReadOnlyList<EncryptedDnsProvisioningServiceParameter> normalizedParameters =
            EncryptedDnsProvisioningServiceParameter.Normalize(serviceParameters ?? [EncryptedDnsProvisioningServiceParameter.FromPresentationKey("alpn")]);

        if (adnOnly)
        {
            return CreateAdnOnlyPlan(
                authenticationDomainName,
                servicePriority,
                lifetime,
                publishDhcpv4,
                publishDhcpv6,
                publishRouterAdvertisements);
        }

        List<IPAddress> ipv4Addresses = [];
        List<IPAddress> ipv6Addresses = [];
        AddUsableAddresses(lanFacingAddresses, ipv4Addresses, ipv6Addresses);

        EncryptedDnsDiscoveryDhcpv4Option? dhcpv4Option = null;
        if (publishDhcpv4 && ipv4Addresses.Count != 0)
        {
            dhcpv4Option = EncryptedDnsDiscoveryDhcpv4Option.Create(
            [
                EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateInstance(
                    authenticationDomainName,
                    ipv4Addresses,
                    servicePriority,
                    normalizedParameters)
            ]);
        }

        List<EncryptedDnsDiscoveryDhcpv6Option> dhcpv6Options = [];
        if (publishDhcpv6 && ipv6Addresses.Count != 0)
        {
            dhcpv6Options.Add(EncryptedDnsDiscoveryDhcpv6Option.Create(
                authenticationDomainName,
                ipv6Addresses,
                servicePriority,
                normalizedParameters));
        }

        List<EncryptedDnsDiscoveryNeighborDiscoveryOption> routerAdvertisementOptions = [];
        if (publishRouterAdvertisements && ipv6Addresses.Count != 0)
        {
            routerAdvertisementOptions.Add(EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
                authenticationDomainName,
                ipv6Addresses,
                servicePriority,
                lifetime,
                normalizedParameters));
        }

        bool ready = dhcpv4Option is not null || dhcpv6Options.Count != 0 || routerAdvertisementOptions.Count != 0;
        return new EncryptedDnsDiscoveryAdvertisementPlan(
            ready ? EncryptedDnsDiscoveryAdvertisementStatus.Ready : EncryptedDnsDiscoveryAdvertisementStatus.NoUsableAddresses,
            dhcpv4Option,
            dhcpv6Options,
            routerAdvertisementOptions,
            adnOnly: false);
    }

    private static EncryptedDnsDiscoveryAdvertisementPlan CreateAdnOnlyPlan(
        string authenticationDomainName,
        ushort servicePriority,
        uint lifetime,
        bool publishDhcpv4,
        bool publishDhcpv6,
        bool publishRouterAdvertisements)
    {
        EncryptedDnsDiscoveryDhcpv4Option? dhcpv4Option = publishDhcpv4
            ? EncryptedDnsDiscoveryDhcpv4Option.Create(
                [EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance.CreateAdnOnly(authenticationDomainName, servicePriority)])
            : null;

        List<EncryptedDnsDiscoveryDhcpv6Option> dhcpv6Options = publishDhcpv6
            ? [EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly(authenticationDomainName, servicePriority)]
            : [];

        List<EncryptedDnsDiscoveryNeighborDiscoveryOption> routerAdvertisementOptions = publishRouterAdvertisements
            ? [EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly(authenticationDomainName, servicePriority, lifetime)]
            : [];

        return new EncryptedDnsDiscoveryAdvertisementPlan(
            EncryptedDnsDiscoveryAdvertisementStatus.Ready,
            dhcpv4Option,
            dhcpv6Options,
            routerAdvertisementOptions,
            adnOnly: true);
    }

    private static void AddUsableAddresses(
        IEnumerable<IPAddress>? addresses,
        List<IPAddress> ipv4Addresses,
        List<IPAddress> ipv6Addresses)
    {
        if (addresses is null)
        {
            return;
        }

        foreach (IPAddress? address in addresses)
        {
            if (!EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
            {
                continue;
            }

            if (address!.AddressFamily == AddressFamily.InterNetwork)
            {
                ipv4Addresses.Add(address);
            }
            else if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                ipv6Addresses.Add(address);
            }
        }
    }
}
