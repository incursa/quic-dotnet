// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Incursa.Quic.Dns;

/// <summary>
/// Validated scalar model for RFC 9464 encrypted DNS provisioning configuration attributes.
/// </summary>
public sealed class EncryptedDnsProvisioningAttribute
{
    private const int MaximumAuthenticationDomainNameLength = 255;
    private const int MaximumDnsLabelLength = 63;
    private const ushort EmptyLength = 0;
    private const int IpAttributeFixedDataLength = 4;
    private const int Ipv4AddressOctets = 4;
    private const int Ipv6AddressOctets = 16;

    private EncryptedDnsProvisioningAttribute(
        EncryptedDnsProvisioningPayloadType payloadType,
        EncryptedDnsProvisioningAddressFamily addressFamily,
        ushort length,
        byte addressCount,
        string authenticationDomainName,
        ReadOnlyCollection<IPAddress> addresses,
        ReadOnlyCollection<string> serviceParameterKeys,
        bool omitsTrailingFields)
    {
        PayloadType = payloadType;
        AddressFamily = addressFamily;
        Length = length;
        AddressCount = addressCount;
        AuthenticationDomainName = authenticationDomainName;
        Addresses = addresses;
        ServiceParameterKeys = serviceParameterKeys;
        OmitsTrailingFields = omitsTrailingFields;
    }

    /// <summary>
    /// Gets the size, in octets, of the RFC 9464 Length field.
    /// </summary>
    public const int LengthFieldOctets = 2;

    /// <summary>
    /// Gets the size, in octets, of the RFC 9464 ADN Length field.
    /// </summary>
    public const int AuthenticationDomainNameLengthFieldOctets = 1;

    /// <summary>
    /// Gets the ENCDNS_DIGEST_INFO attribute type.
    /// </summary>
    public const ushort DigestInfoAttributeType = 29;

    /// <summary>
    /// Gets a value indicating whether outbound attributes set the reserved bit.
    /// </summary>
    public bool ReservedBitSet => false;

    /// <summary>
    /// Gets the configuration payload type for this attribute.
    /// </summary>
    public EncryptedDnsProvisioningPayloadType PayloadType { get; }

    /// <summary>
    /// Gets the ENCDNS_IP* address family.
    /// </summary>
    public EncryptedDnsProvisioningAddressFamily AddressFamily { get; }

    /// <summary>
    /// Gets the two-octet Length field value.
    /// </summary>
    public ushort Length { get; }

    /// <summary>
    /// Gets the Num Addresses field value.
    /// </summary>
    public byte AddressCount { get; }

    /// <summary>
    /// Gets the DNS presentation-form authentication domain name, or an empty string for zero-length attributes.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the addresses carried by the attribute.
    /// </summary>
    public IReadOnlyList<IPAddress> Addresses { get; }

    /// <summary>
    /// Gets normalized service parameter keys that apply to all addresses.
    /// </summary>
    public IReadOnlyCollection<string> ServiceParameterKeys { get; }

    /// <summary>
    /// Gets a value indicating whether zero Length omits all trailing fields.
    /// </summary>
    public bool OmitsTrailingFields { get; }

    /// <summary>
    /// Returns true when a received reserved bit can be ignored.
    /// </summary>
    public static bool ShouldIgnoreReservedBit(bool reservedBitSet) => reservedBitSet || !reservedBitSet;

    /// <summary>
    /// Creates a zero-length ENCDNS_IP* attribute for CFG_REQUEST without a specific resolver or CFG_ACK.
    /// </summary>
    public static EncryptedDnsProvisioningAttribute CreateEmpty(
        EncryptedDnsProvisioningPayloadType payloadType,
        EncryptedDnsProvisioningAddressFamily addressFamily)
    {
        if (payloadType is not EncryptedDnsProvisioningPayloadType.Request and not EncryptedDnsProvisioningPayloadType.Ack)
        {
            throw new ArgumentException("Only CFG_REQUEST without a resolver and CFG_ACK can use zero ENCDNS_IP* length.", nameof(payloadType));
        }

        return new EncryptedDnsProvisioningAttribute(
            payloadType,
            addressFamily,
            EmptyLength,
            addressCount: 0,
            authenticationDomainName: string.Empty,
            new ReadOnlyCollection<IPAddress>([]),
            new ReadOnlyCollection<string>([]),
            omitsTrailingFields: true);
    }

    /// <summary>
    /// Creates a populated ENCDNS_IP* attribute and computes its RFC 9464 length.
    /// </summary>
    public static EncryptedDnsProvisioningAttribute CreateAddressList(
        EncryptedDnsProvisioningPayloadType payloadType,
        EncryptedDnsProvisioningAddressFamily addressFamily,
        string authenticationDomainName,
        IEnumerable<IPAddress> addresses,
        IEnumerable<string>? serviceParameterKeys = null)
    {
        if (payloadType == EncryptedDnsProvisioningPayloadType.Ack)
        {
            throw new ArgumentException("CFG_ACK ENCDNS_IP* attributes must use zero-length data.", nameof(payloadType));
        }

        string normalizedName = NormalizeAuthenticationDomainName(authenticationDomainName);
        int authenticationNameLength = Encoding.ASCII.GetByteCount(normalizedName);
        if (authenticationNameLength > byte.MaxValue)
        {
            throw new ArgumentException("The authentication domain name must fit in the one-octet ADN Length field.", nameof(authenticationDomainName));
        }

        List<IPAddress> normalizedAddresses = NormalizeAddresses(addressFamily, addresses);
        if (normalizedAddresses.Count == 0)
        {
            throw new ArgumentException("An ENCDNS_IP* attribute with non-zero length must contain at least one address.", nameof(addresses));
        }

        if (normalizedAddresses.Count > byte.MaxValue)
        {
            throw new ArgumentException("The address count must fit in the one-octet Num Addresses field.", nameof(addresses));
        }

        ReadOnlyCollection<string> normalizedServiceParameterKeys = NormalizeServiceParameterKeys(serviceParameterKeys);
        int serviceParameterLength = GetServiceParameterLength(normalizedServiceParameterKeys);
        int addressOctets = addressFamily == EncryptedDnsProvisioningAddressFamily.Ip4
            ? Ipv4AddressOctets
            : Ipv6AddressOctets;
        int length = IpAttributeFixedDataLength + authenticationNameLength + (normalizedAddresses.Count * addressOctets) + serviceParameterLength;
        if (length > ushort.MaxValue)
        {
            throw new ArgumentException("The ENCDNS_IP* attribute length must fit in the two-octet Length field.", nameof(addresses));
        }

        return new EncryptedDnsProvisioningAttribute(
            payloadType,
            addressFamily,
            (ushort)length,
            (byte)normalizedAddresses.Count,
            normalizedName,
            new ReadOnlyCollection<IPAddress>(normalizedAddresses),
            normalizedServiceParameterKeys,
            omitsTrailingFields: false);
    }

    private static string NormalizeAuthenticationDomainName(string? authenticationDomainName)
    {
        if (string.IsNullOrWhiteSpace(authenticationDomainName))
        {
            throw new ArgumentException("The authentication domain name is required.", nameof(authenticationDomainName));
        }

        if (authenticationDomainName.IndexOf('\0', StringComparison.Ordinal) >= 0
            || authenticationDomainName.IndexOf('\r', StringComparison.Ordinal) >= 0
            || authenticationDomainName.IndexOf('\n', StringComparison.Ordinal) >= 0)
        {
            throw new ArgumentException("The authentication domain name must not contain terminators.", nameof(authenticationDomainName));
        }

        string candidate = authenticationDomainName.Trim();
        if (candidate.Length > MaximumAuthenticationDomainNameLength)
        {
            throw new ArgumentException("The authentication domain name is not valid DNS presentation form.", nameof(authenticationDomainName));
        }

        if (IPAddress.TryParse(candidate, out _) || candidate is ['[', .., ']'])
        {
            throw new ArgumentException("The authentication domain name must be a fully qualified domain name.", nameof(authenticationDomainName));
        }

        string host = candidate.EndsWith(".", StringComparison.Ordinal) ? candidate[..^1] : candidate;
        if (host.Length == 0)
        {
            throw new ArgumentException("The authentication domain name is required.", nameof(authenticationDomainName));
        }

        string[] labels = host.Split('.');
        foreach (string label in labels)
        {
            if (label.Length is 0 or > MaximumDnsLabelLength || label[0] == '-' || label[^1] == '-')
            {
                throw new ArgumentException("The authentication domain name is not valid DNS presentation form.", nameof(authenticationDomainName));
            }

            foreach (char c in label)
            {
                bool valid = c is >= 'a' and <= 'z'
                    || c is >= 'A' and <= 'Z'
                    || c is >= '0' and <= '9'
                    || c == '-';
                if (!valid)
                {
                    throw new ArgumentException("The authentication domain name must use DNS A-label presentation form.", nameof(authenticationDomainName));
                }
            }
        }

        return string.Join(".", labels).ToLowerInvariant() + ".";
    }

    private static List<IPAddress> NormalizeAddresses(
        EncryptedDnsProvisioningAddressFamily addressFamily,
        IEnumerable<IPAddress>? addresses)
    {
        if (addresses is null)
        {
            throw new ArgumentNullException(nameof(addresses));
        }

        AddressFamily expectedFamily = addressFamily == EncryptedDnsProvisioningAddressFamily.Ip4
            ? System.Net.Sockets.AddressFamily.InterNetwork
            : System.Net.Sockets.AddressFamily.InterNetworkV6;
        List<IPAddress> normalized = [];
        foreach (IPAddress? address in addresses)
        {
            if (address is null || address.AddressFamily != expectedFamily)
            {
                throw new ArgumentException("The ENCDNS_IP* address family does not match the supplied address.", nameof(addresses));
            }

            normalized.Add(address);
        }

        return normalized;
    }

    private static ReadOnlyCollection<string> NormalizeServiceParameterKeys(IEnumerable<string>? serviceParameterKeys)
    {
        if (serviceParameterKeys is null)
        {
            return new ReadOnlyCollection<string>([]);
        }

        List<string> normalized = [];
        foreach (string? key in serviceParameterKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("SvcParam keys must not be empty.", nameof(serviceParameterKeys));
            }

            string trimmed = key.Trim().ToLowerInvariant();
            if (EncryptedDnsDiscoveryOption.IsForbiddenAddressHintServiceParameter(trimmed))
            {
                throw new ArgumentException("RFC 9464 ENCDNS_IP* attributes must not include ipv4hint or ipv6hint SvcParams.", nameof(serviceParameterKeys));
            }

            normalized.Add(trimmed);
        }

        return new ReadOnlyCollection<string>(normalized);
    }

    private static int GetServiceParameterLength(IEnumerable<string> serviceParameterKeys)
    {
        int length = 0;
        foreach (string key in serviceParameterKeys)
        {
            length += Encoding.ASCII.GetByteCount(key);
        }

        return length;
    }
}
