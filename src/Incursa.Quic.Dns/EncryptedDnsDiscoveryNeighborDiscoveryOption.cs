// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9463 Neighbor Discovery encrypted DNS option wire-format helper.
/// </summary>
public sealed class EncryptedDnsDiscoveryNeighborDiscoveryOption
{
    private const int OptionHeaderOctets = 2;
    private const int UInt16FieldOctets = 2;
    private const int UInt32FieldOctets = 4;
    private const int FixedDataWithoutTrailingFieldsOctets = 8;
    private const int AddressLengthFieldOctets = 2;
    private const int ServiceParametersLengthFieldOctets = 2;
    private const int Ipv6AddressOctets = 16;
    private const int OptionLengthUnitOctets = 8;
    private const int MaximumDnsLabelLength = 63;
    private const uint DefaultLifetimeMultiplier = 3;

    private readonly byte[] authenticationDomainNameWire;

    private EncryptedDnsDiscoveryNeighborDiscoveryOption(
        ushort servicePriority,
        uint lifetime,
        string authenticationDomainName,
        ReadOnlyMemory<byte> authenticationDomainNameWire,
        ReadOnlyCollection<IPAddress> addresses,
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters)
    {
        ServicePriority = servicePriority;
        Lifetime = lifetime;
        AuthenticationDomainName = authenticationDomainName;
        this.authenticationDomainNameWire = authenticationDomainNameWire.ToArray();
        Addresses = addresses;
        ServiceParameters = serviceParameters;
    }

    /// <summary>
    /// Gets the Neighbor Discovery encrypted DNS option type.
    /// </summary>
    public byte OptionType => EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType;

    /// <summary>
    /// Gets the encoded option length in 8-octet units, including Type and Length.
    /// </summary>
    public byte LengthUnits => checked((byte)(EncodedLength / OptionLengthUnitOctets));

    /// <summary>
    /// Gets the encoded option length in octets, including padding.
    /// </summary>
    public int EncodedLength => RoundUpToLengthUnit(UnpaddedLength);

    /// <summary>
    /// Gets the 16-bit service priority.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the 32-bit lifetime value.
    /// </summary>
    public uint Lifetime { get; }

    /// <summary>
    /// Gets a value indicating whether <see cref="Lifetime" /> represents infinity.
    /// </summary>
    public bool HasInfiniteLifetime => Lifetime == EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime;

    /// <summary>
    /// Gets a value indicating whether <see cref="Lifetime" /> retires the ADN.
    /// </summary>
    public bool RetiresAuthenticationDomainName => Lifetime == EncryptedDnsDiscoveryOptionCodes.RetiringLifetime;

    /// <summary>
    /// Gets the normalized authentication domain name.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the RFC 8415 DNS wire-format authentication domain name.
    /// </summary>
    public ReadOnlyMemory<byte> AuthenticationDomainNameWire => authenticationDomainNameWire;

    /// <summary>
    /// Gets the ADN Length field value.
    /// </summary>
    public ushort AuthenticationDomainNameLength => checked((ushort)authenticationDomainNameWire.Length);

    /// <summary>
    /// Gets usable IPv6 resolver addresses.
    /// </summary>
    public IReadOnlyList<IPAddress> Addresses { get; }

    /// <summary>
    /// Gets the Addr Length field value.
    /// </summary>
    public ushort AddressLength => checked((ushort)(Addresses.Count * Ipv6AddressOctets));

    /// <summary>
    /// Gets the RFC 9460 SvcParams attached to the option.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningServiceParameter> ServiceParameters { get; }

    /// <summary>
    /// Gets the SvcParams Length field value.
    /// </summary>
    public ushort ServiceParametersLength => checked((ushort)ServiceParameters.Sum(static parameter => parameter.EncodedLength));

    /// <summary>
    /// Gets the number of zero padding octets added to reach an 8-octet boundary.
    /// </summary>
    public int PaddingLength => EncodedLength - UnpaddedLength;

    /// <summary>
    /// Gets a value indicating whether this option omits Addr Length, IPv6 addresses, and SvcParams.
    /// </summary>
    public bool UsesAdnOnlyMode => Addresses.Count == 0 && ServiceParameters.Count == 0;

    private int UnpaddedLength => OptionHeaderOctets
        + FixedDataWithoutTrailingFieldsOctets
        + AuthenticationDomainNameLength
        + (UsesAdnOnlyMode ? 0 : AddressLengthFieldOctets + AddressLength + ServiceParametersLengthFieldOctets + ServiceParametersLength);

    /// <summary>
    /// Creates an ADN-only Neighbor Discovery encrypted DNS option.
    /// </summary>
    public static EncryptedDnsDiscoveryNeighborDiscoveryOption CreateAdnOnly(
        string authenticationDomainName,
        ushort servicePriority = 0,
        uint lifetime = EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime)
    {
        return Create(
            authenticationDomainName,
            addresses: [],
            servicePriority,
            lifetime,
            serviceParameters: [],
            requireAlpnServiceParameter: false);
    }

    /// <summary>
    /// Creates a populated Neighbor Discovery encrypted DNS option.
    /// </summary>
    public static EncryptedDnsDiscoveryNeighborDiscoveryOption Create(
        string authenticationDomainName,
        IEnumerable<IPAddress> addresses,
        ushort servicePriority = 0,
        uint lifetime = EncryptedDnsDiscoveryOptionCodes.InfiniteLifetime,
        IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters = null,
        bool requireAlpnServiceParameter = true)
    {
        string normalizedName = EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(authenticationDomainName);
        byte[] encodedName = EncodeAuthenticationDomainName(normalizedName);
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> normalizedServiceParameters =
            EncryptedDnsProvisioningServiceParameter.Normalize(serviceParameters);
        if (requireAlpnServiceParameter && !normalizedServiceParameters.Any(static parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey))
        {
            throw new ArgumentException("Neighbor Discovery encrypted DNS SvcParams should include the alpn SvcParam unless ALPN preference is explicitly disabled.", nameof(serviceParameters));
        }

        List<IPAddress> normalizedAddresses = NormalizeIpv6Addresses(addresses);
        if (normalizedAddresses.Count == 0 && normalizedServiceParameters.Count != 0)
        {
            throw new ArgumentException("Neighbor Discovery encrypted DNS options with SvcParams must also include IPv6 resolver addresses.", nameof(addresses));
        }

        return new EncryptedDnsDiscoveryNeighborDiscoveryOption(
            servicePriority,
            lifetime,
            normalizedName,
            encodedName,
            new ReadOnlyCollection<IPAddress>(normalizedAddresses),
            normalizedServiceParameters);
    }

    /// <summary>
    /// Computes the RFC 9463 recommended default lifetime from the RA MaxRtrAdvInterval value.
    /// </summary>
    public static uint GetDefaultLifetimeSeconds(uint maxRtrAdvIntervalSeconds)
    {
        return checked(maxRtrAdvIntervalSeconds * DefaultLifetimeMultiplier);
    }

    /// <summary>
    /// Gets the RFC 9463 default port for a DNS ALPN identifier when no port SvcParam is present.
    /// </summary>
    public static int GetDefaultPortForAlpn(string alpnProtocol)
        => EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn(alpnProtocol);

    /// <summary>
    /// Encodes this Neighbor Discovery option.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[EncodedLength];
        encoded[0] = OptionType;
        encoded[1] = LengthUnits;

        int offset = OptionHeaderOctets;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), ServicePriority);
        offset += UInt16FieldOctets;
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(offset), Lifetime);
        offset += UInt32FieldOctets;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), AuthenticationDomainNameLength);
        offset += UInt16FieldOctets;
        authenticationDomainNameWire.CopyTo(encoded.AsSpan(offset));
        offset += authenticationDomainNameWire.Length;

        if (!UsesAdnOnlyMode)
        {
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), AddressLength);
            offset += UInt16FieldOctets;
            foreach (IPAddress address in Addresses)
            {
                address.GetAddressBytes().CopyTo(encoded, offset);
                offset += Ipv6AddressOctets;
            }

            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), ServiceParametersLength);
            offset += UInt16FieldOctets;
            foreach (EncryptedDnsProvisioningServiceParameter parameter in ServiceParameters)
            {
                parameter.WriteTo(encoded.AsSpan(offset, parameter.EncodedLength));
                offset += parameter.EncodedLength;
            }
        }

        return encoded;
    }

    /// <summary>
    /// Decodes one Neighbor Discovery encrypted DNS option.
    /// </summary>
    public static EncryptedDnsDiscoveryNeighborDiscoveryOption Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < OptionHeaderOctets + FixedDataWithoutTrailingFieldsOctets)
        {
            throw new ArgumentException("The Neighbor Discovery encrypted DNS option is shorter than the fixed fields.", nameof(encoded));
        }

        if (encoded[0] != EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType)
        {
            throw new ArgumentException("The Neighbor Discovery option type is not the encrypted DNS option.", nameof(encoded));
        }

        int encodedLength = encoded[1] * OptionLengthUnitOctets;
        if (encodedLength == 0 || encodedLength != encoded.Length)
        {
            throw new ArgumentException("The Neighbor Discovery option length does not match the encoded option size.", nameof(encoded));
        }

        int offset = OptionHeaderOctets;
        ushort servicePriority = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += UInt16FieldOctets;
        uint lifetime = BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
        offset += UInt32FieldOctets;
        ushort authenticationNameLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += UInt16FieldOctets;
        if (encoded.Length - offset < authenticationNameLength)
        {
            throw new ArgumentException("The Neighbor Discovery ADN Length exceeds the option data.", nameof(encoded));
        }

        string authenticationDomainName = DecodeAuthenticationDomainName(encoded.Slice(offset, authenticationNameLength));
        offset += authenticationNameLength;
        if (IsZeroPadding(encoded[offset..]))
        {
            return CreateAdnOnly(authenticationDomainName, servicePriority, lifetime);
        }

        if (encoded.Length - offset < AddressLengthFieldOctets)
        {
            throw new ArgumentException("The Neighbor Discovery option ends inside Addr Length.", nameof(encoded));
        }

        ushort addressLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += UInt16FieldOctets;
        if (addressLength == 0 || addressLength % Ipv6AddressOctets != 0)
        {
            throw new ArgumentException("The Neighbor Discovery Addr Length must be a non-zero multiple of 16.", nameof(encoded));
        }

        if (encoded.Length - offset < addressLength + ServiceParametersLengthFieldOctets)
        {
            throw new ArgumentException("The Neighbor Discovery Addr Length exceeds the option data.", nameof(encoded));
        }

        List<IPAddress> addresses = [];
        int addressEnd = offset + addressLength;
        while (offset < addressEnd)
        {
            IPAddress address = new(encoded.Slice(offset, Ipv6AddressOctets));
            if (EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
            {
                addresses.Add(address);
            }

            offset += Ipv6AddressOctets;
        }

        if (addresses.Count == 0)
        {
            throw new ArgumentException("The Neighbor Discovery option does not contain a usable IPv6 resolver address.", nameof(encoded));
        }

        ushort serviceParametersLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += UInt16FieldOctets;
        if (encoded.Length - offset < serviceParametersLength)
        {
            throw new ArgumentException("The Neighbor Discovery SvcParams Length exceeds the option data.", nameof(encoded));
        }

        ReadOnlySpan<byte> serviceParameterBytes = encoded.Slice(offset, serviceParametersLength);
        offset += serviceParametersLength;
        if (!IsZeroPadding(encoded[offset..]))
        {
            throw new ArgumentException("The Neighbor Discovery option padding must be zero.", nameof(encoded));
        }

        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters =
            EncryptedDnsProvisioningServiceParameter.DecodeMany(serviceParameterBytes);
        return Create(authenticationDomainName, addresses, servicePriority, lifetime, serviceParameters, requireAlpnServiceParameter: false);
    }

    /// <summary>
    /// Decodes multiple Neighbor Discovery encrypted DNS options and returns them in service-priority order.
    /// </summary>
    public static IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> DecodeMany(
        IEnumerable<ReadOnlyMemory<byte>> encodedOptions,
        bool silentlyDiscardInvalidOptions = true)
    {
        ArgumentNullException.ThrowIfNull(encodedOptions);

        List<EncryptedDnsDiscoveryNeighborDiscoveryOption> options = [];
        foreach (ReadOnlyMemory<byte> encoded in encodedOptions)
        {
            try
            {
                options.Add(Decode(encoded.Span));
            }
            catch (ArgumentException) when (silentlyDiscardInvalidOptions)
            {
                continue;
            }
        }

        options.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        return new ReadOnlyCollection<EncryptedDnsDiscoveryNeighborDiscoveryOption>(options);
    }

    private static List<IPAddress> NormalizeIpv6Addresses(IEnumerable<IPAddress>? addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        List<IPAddress> normalized = [];
        foreach (IPAddress? address in addresses)
        {
            if (address is null || address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException("Neighbor Discovery encrypted DNS addresses must be IPv6 addresses.", nameof(addresses));
            }

            if (EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
            {
                normalized.Add(address);
            }
        }

        return normalized;
    }

    private static byte[] EncodeAuthenticationDomainName(string authenticationDomainName)
    {
        string host = authenticationDomainName.EndsWith(".", StringComparison.Ordinal)
            ? authenticationDomainName[..^1]
            : authenticationDomainName;
        string[] labels = host.Split('.');
        int length = labels.Sum(static label => 1 + label.Length) + 1;
        byte[] encoded = new byte[length];
        int offset = 0;
        foreach (string label in labels)
        {
            encoded[offset++] = checked((byte)label.Length);
            foreach (char c in label)
            {
                encoded[offset++] = checked((byte)c);
            }
        }

        encoded[offset] = 0;
        return encoded;
    }

    private static string DecodeAuthenticationDomainName(ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty || encoded[^1] != 0)
        {
            throw new ArgumentException("The Neighbor Discovery authentication-domain-name must be a complete RFC 8415 DNS name.", nameof(encoded));
        }

        List<string> labels = [];
        int offset = 0;
        while (offset < encoded.Length)
        {
            byte labelLength = encoded[offset++];
            if (labelLength == 0)
            {
                if (offset != encoded.Length)
                {
                    throw new ArgumentException("The Neighbor Discovery authentication-domain-name contains trailing data after the root label.", nameof(encoded));
                }

                return EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(string.Join(".", labels));
            }

            if (labelLength > MaximumDnsLabelLength || encoded.Length - offset < labelLength)
            {
                throw new ArgumentException("The Neighbor Discovery authentication-domain-name contains an invalid DNS label.", nameof(encoded));
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(encoded.Slice(offset, labelLength)));
            offset += labelLength;
        }

        throw new ArgumentException("The Neighbor Discovery authentication-domain-name is incomplete.", nameof(encoded));
    }

    private static bool IsZeroPadding(ReadOnlySpan<byte> padding)
    {
        foreach (byte value in padding)
        {
            if (value != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static int RoundUpToLengthUnit(int length)
    {
        int remainder = length % OptionLengthUnitOctets;
        return remainder == 0 ? length : checked(length + (OptionLengthUnitOctets - remainder));
    }
}
