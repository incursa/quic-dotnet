// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Pure client-side RFC 9463 policy for consuming encrypted DNS discovery data.
/// </summary>
public static class EncryptedDnsDiscoveryClientPolicy
{
    /// <summary>
    /// Creates a resolver plan from DHCP and Router Advertisement encrypted DNS discovery options.
    /// </summary>
    public static EncryptedDnsDiscoveryClientPlan CreatePlan(
        IEnumerable<EncryptedDnsDiscoveryOption>? dhcpOptions = null,
        IEnumerable<EncryptedDnsDiscoveryOption>? routerAdvertisementOptions = null,
        IEnumerable<IPAddress>? do53ResolverAddresses = null,
        bool explicitConfigurationPrefersDo53 = false,
        bool encryptedConnectionEstablished = true,
        bool allowDo53Fallback = true,
        bool useExplicitTrustAnchors = false)
    {
        List<EncryptedDnsDiscoveryResolverEndpoint> endpoints = [];
        AddEndpoints(endpoints, dhcpOptions, EncryptedDnsDiscoverySource.Dhcp);
        AddEndpoints(endpoints, routerAdvertisementOptions, EncryptedDnsDiscoverySource.RouterAdvertisement);
        endpoints.Sort(static (left, right) =>
        {
            int sourceComparison = GetSourcePrecedence(left.Source).CompareTo(GetSourcePrecedence(right.Source));
            return sourceComparison != 0
                ? sourceComparison
                : left.ServicePriority.CompareTo(right.ServicePriority);
        });

        EncryptedDnsDiscoveryTrustAnchorMode trustAnchorMode = useExplicitTrustAnchors
            ? EncryptedDnsDiscoveryTrustAnchorMode.Explicit
            : EncryptedDnsDiscoveryTrustAnchorMode.DefaultSystemOrApplication;

        return EncryptedDnsDiscoveryClientPlan.Create(
            endpoints,
            NormalizeDo53Resolvers(do53ResolverAddresses),
            explicitConfigurationPrefersDo53,
            encryptedConnectionEstablished,
            allowDo53Fallback,
            trustAnchorMode);
    }

    /// <summary>
    /// Validates an encrypted DNS resolver certificate using PKIX and the conveyed ADN comparison result.
    /// </summary>
    public static EncryptedDnsDiscoveryCertificateValidationStatus ValidateResolverCertificate(
        EncryptedDnsDiscoveryResolverEndpoint resolverEndpoint,
        bool pkixValidationSucceeded,
        bool authenticationDomainNameMatchesCertificate)
    {
        ArgumentNullException.ThrowIfNull(resolverEndpoint);
        return pkixValidationSucceeded && authenticationDomainNameMatchesCertificate
            ? EncryptedDnsDiscoveryCertificateValidationStatus.Validated
            : EncryptedDnsDiscoveryCertificateValidationStatus.Failed;
    }

    private static void AddEndpoints(
        List<EncryptedDnsDiscoveryResolverEndpoint> endpoints,
        IEnumerable<EncryptedDnsDiscoveryOption>? options,
        EncryptedDnsDiscoverySource source)
    {
        if (options is null)
        {
            return;
        }

        foreach (EncryptedDnsDiscoveryOption? option in options)
        {
            ArgumentNullException.ThrowIfNull(option);
            foreach (IPAddress address in option.Addresses)
            {
                endpoints.Add(new EncryptedDnsDiscoveryResolverEndpoint(
                    address,
                    option.AuthenticationDomainName,
                    option.ServicePriority,
                    option.Lifetime,
                    source,
                    option.ServiceParameterKeys));
            }
        }
    }

    private static int GetSourcePrecedence(EncryptedDnsDiscoverySource source)
        => source == EncryptedDnsDiscoverySource.Dhcp ? 0 : 1;

    private static List<IPAddress> NormalizeDo53Resolvers(IEnumerable<IPAddress>? do53ResolverAddresses)
    {
        List<IPAddress> normalized = [];
        if (do53ResolverAddresses is null)
        {
            return normalized;
        }

        foreach (IPAddress? address in do53ResolverAddresses)
        {
            ArgumentNullException.ThrowIfNull(address);
            normalized.Add(address);
        }

        return normalized;
    }
}
