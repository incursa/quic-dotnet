// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;

namespace Incursa.Quic.Dns;

/// <summary>
/// Validated scalar representation of an RFC 9463 encrypted DNS discovery option.
/// </summary>
public sealed class EncryptedDnsDiscoveryOption
{
    private const int MaximumDnsNameLength = 253;
    private const int MaximumDnsLabelLength = 63;
    private const byte Ipv4MulticastFirstOctetMinimum = 224;
    private const byte Ipv4MulticastFirstOctetMaximum = 239;

    private EncryptedDnsDiscoveryOption(
        ushort servicePriority,
        string authenticationDomainName,
        ReadOnlyCollection<IPAddress> addresses,
        uint lifetime,
        ReadOnlyCollection<string> serviceParameterKeys)
    {
        ServicePriority = servicePriority;
        AuthenticationDomainName = authenticationDomainName;
        Addresses = addresses;
        Lifetime = lifetime;
        ServiceParameterKeys = serviceParameterKeys;
    }

    /// <summary>
    /// Gets the 16-bit SVCB service priority.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the normalized fully qualified authentication domain name.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets usable encrypted DNS resolver addresses after host-only address filtering.
    /// </summary>
    public IReadOnlyList<IPAddress> Addresses { get; }

    /// <summary>
    /// Gets the Router Advertisement lifetime value associated with the ADN.
    /// </summary>
    public uint Lifetime { get; }

    /// <summary>
    /// Gets the SvcParam keys after RFC 9463 validation.
    /// </summary>
    public IReadOnlyCollection<string> ServiceParameterKeys { get; }

    /// <summary>
    /// Gets a value indicating whether <see cref="Lifetime" /> represents infinity.
    /// </summary>
    public bool HasInfiniteLifetime => Lifetime == EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime;

    /// <summary>
    /// Gets a value indicating whether <see cref="Lifetime" /> retires the ADN.
    /// </summary>
    public bool RetiresAuthenticationDomainName => Lifetime == EncryptedDnsDiscoveryOptionCodes.RetiringLifetime;

    /// <summary>
    /// Creates an RFC 9463 encrypted DNS discovery option or throws when validation fails.
    /// </summary>
    public static EncryptedDnsDiscoveryOption Create(
        string authenticationDomainName,
        IEnumerable<IPAddress> addresses,
        ushort servicePriority = 0,
        uint lifetime = EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime,
        IEnumerable<string>? serviceParameterKeys = null)
    {
        if (TryCreate(authenticationDomainName, addresses, out EncryptedDnsDiscoveryOption? option, servicePriority, lifetime, serviceParameterKeys))
        {
            return option!;
        }

        throw new ArgumentException("The encrypted DNS discovery option is not valid.", nameof(authenticationDomainName));
    }

    /// <summary>
    /// Creates an RFC 9463 encrypted DNS discovery option when validation succeeds.
    /// </summary>
    public static bool TryCreate(
        string? authenticationDomainName,
        IEnumerable<IPAddress>? addresses,
        out EncryptedDnsDiscoveryOption? option,
        ushort servicePriority = 0,
        uint lifetime = EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime,
        IEnumerable<string>? serviceParameterKeys = null)
    {
        option = null;
        if (!TryNormalizeAuthenticationDomainName(authenticationDomainName, out string normalizedName))
        {
            return false;
        }

        if (addresses is null)
        {
            return false;
        }

        List<IPAddress> usableAddresses = [];
        foreach (IPAddress? address in addresses)
        {
            if (IsUsableResolverAddress(address))
            {
                usableAddresses.Add(address);
            }
        }

        if (usableAddresses.Count == 0)
        {
            return false;
        }

        if (!TryNormalizeServiceParameterKeys(serviceParameterKeys, out ReadOnlyCollection<string> normalizedServiceParameterKeys))
        {
            return false;
        }

        option = new EncryptedDnsDiscoveryOption(
            servicePriority,
            normalizedName,
            new ReadOnlyCollection<IPAddress>(usableAddresses),
            lifetime,
            normalizedServiceParameterKeys);
        return true;
    }

    /// <summary>
    /// Returns true when the SvcParam key is forbidden inside an RFC 9463 encrypted DNS option.
    /// </summary>
    public static bool IsForbiddenAddressHintServiceParameter(string? serviceParameterKey)
        => string.Equals(serviceParameterKey, EncryptedDnsDiscoveryOptionCodes.Ipv4HintServiceParameterKey, StringComparison.OrdinalIgnoreCase)
            || string.Equals(serviceParameterKey, EncryptedDnsDiscoveryOptionCodes.Ipv6HintServiceParameterKey, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Returns true when the address can be used as an encrypted DNS resolver address after RFC 9463 host filtering.
    /// </summary>
    public static bool IsUsableResolverAddress(IPAddress? address)
    {
        if (address is null
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast)
            || IPAddress.IsLoopback(address))
        {
            return false;
        }

        return address.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork => !IsIpv4Multicast(address),
            System.Net.Sockets.AddressFamily.InterNetworkV6 => !address.IsIPv6Multicast,
            _ => false,
        };
    }

    private static bool TryNormalizeServiceParameterKeys(
        IEnumerable<string>? serviceParameterKeys,
        out ReadOnlyCollection<string> normalizedServiceParameterKeys)
    {
        if (serviceParameterKeys is null)
        {
            normalizedServiceParameterKeys = Array.AsReadOnly(Array.Empty<string>());
            return true;
        }

        List<string> normalized = [];
        foreach (string? key in serviceParameterKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                normalizedServiceParameterKeys = Array.AsReadOnly(Array.Empty<string>());
                return false;
            }

            string trimmed = key.Trim().ToLowerInvariant();
            if (IsForbiddenAddressHintServiceParameter(trimmed))
            {
                normalizedServiceParameterKeys = Array.AsReadOnly(Array.Empty<string>());
                return false;
            }

            normalized.Add(trimmed);
        }

        normalizedServiceParameterKeys = new ReadOnlyCollection<string>(normalized);
        return true;
    }

    private static bool TryNormalizeAuthenticationDomainName(string? authenticationDomainName, out string normalizedName)
    {
        normalizedName = string.Empty;
        if (string.IsNullOrWhiteSpace(authenticationDomainName))
        {
            return false;
        }

        string candidate = authenticationDomainName.Trim();
        if (candidate is ['[', .., ']'] || IPAddress.TryParse(candidate, out _))
        {
            return false;
        }

        bool absolute = candidate.EndsWith(".", StringComparison.Ordinal);
        string host = absolute ? candidate[..^1] : candidate;
        if (host.Length == 0 || host.Length > MaximumDnsNameLength)
        {
            return false;
        }

        string[] labels = host.Split('.');
        foreach (string label in labels)
        {
            if (!IsValidDnsLabel(label))
            {
                return false;
            }
        }

        normalizedName = string.Join(".", labels).ToLowerInvariant() + ".";
        return true;
    }

    private static bool IsValidDnsLabel(string label)
    {
        if (label.Length is 0 or > MaximumDnsLabelLength || label[0] == '-' || label[^1] == '-')
        {
            return false;
        }

        foreach (char c in label)
        {
            bool valid = c is >= 'a' and <= 'z'
                || c is >= 'A' and <= 'Z'
                || c is >= '0' and <= '9'
                || c == '-';
            if (!valid)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsIpv4Multicast(IPAddress address)
    {
        byte firstOctet = address.GetAddressBytes()[0];
        return firstOctet is >= Ipv4MulticastFirstOctetMinimum and <= Ipv4MulticastFirstOctetMaximum;
    }
}
