// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9463 DHCPv6 OPTION_V6_DNR wire-format helper.
/// </summary>
public sealed class EncryptedDnsDiscoveryDhcpv6Option
{
    private const int UInt16FieldOctets = 2;
    private const int OptionHeaderOctets = 4;
    private const int FixedDataWithoutAddressLengthOctets = 4;
    private const int AddressLengthFieldOctets = 2;
    private const int Ipv6AddressOctets = 16;
    private const int MaximumDnsLabelLength = 63;

    private readonly byte[] authenticationDomainNameWire;

    private EncryptedDnsDiscoveryDhcpv6Option(
        ushort servicePriority,
        string authenticationDomainName,
        ReadOnlyMemory<byte> authenticationDomainNameWire,
        ReadOnlyCollection<IPAddress> addresses,
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters)
    {
        ServicePriority = servicePriority;
        AuthenticationDomainName = authenticationDomainName;
        this.authenticationDomainNameWire = authenticationDomainNameWire.ToArray();
        Addresses = addresses;
        ServiceParameters = serviceParameters;
    }

    /// <summary>
    /// Gets the DHCPv6 option code for OPTION_V6_DNR.
    /// </summary>
    public ushort OptionCode => EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr;

    /// <summary>
    /// Gets the enclosed DHCPv6 option data length.
    /// </summary>
    public ushort OptionLength => checked((ushort)(
        FixedDataWithoutAddressLengthOctets
        + AuthenticationDomainNameLength
        + (UsesAdnOnlyMode ? 0 : AddressLengthFieldOctets + AddressLength + ServiceParametersLength)));

    /// <summary>
    /// Gets the 16-bit service priority.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the normalized authentication domain name in DNS presentation form.
    /// </summary>
    public string AuthenticationDomainName { get; }

    /// <summary>
    /// Gets the authentication domain name in RFC 8415 DNS wire format.
    /// </summary>
    public ReadOnlyMemory<byte> AuthenticationDomainNameWire => authenticationDomainNameWire;

    /// <summary>
    /// Gets the ADN Length field value.
    /// </summary>
    public ushort AuthenticationDomainNameLength => checked((ushort)authenticationDomainNameWire.Length);

    /// <summary>
    /// Gets the usable IPv6 resolver addresses.
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
    /// Gets the service parameter field length computed from Option-length, ADN Length, and Addr Length.
    /// </summary>
    public ushort ServiceParametersLength => checked((ushort)ServiceParameters.Sum(static parameter => parameter.EncodedLength));

    /// <summary>
    /// Gets a value indicating whether the option omits Addr Length, IPv6 addresses, and SvcParams.
    /// </summary>
    public bool UsesAdnOnlyMode => Addresses.Count == 0 && ServiceParameters.Count == 0;

    /// <summary>
    /// Creates an ADN-only OPTION_V6_DNR instance.
    /// </summary>
    public static EncryptedDnsDiscoveryDhcpv6Option CreateAdnOnly(
        string authenticationDomainName,
        ushort servicePriority = 0)
    {
        return Create(
            authenticationDomainName,
            addresses: [],
            servicePriority,
            serviceParameters: [],
            requireAlpnServiceParameter: false);
    }

    /// <summary>
    /// Creates a populated OPTION_V6_DNR instance.
    /// </summary>
    public static EncryptedDnsDiscoveryDhcpv6Option Create(
        string authenticationDomainName,
        IEnumerable<IPAddress> addresses,
        ushort servicePriority = 0,
        IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters = null,
        bool requireAlpnServiceParameter = true)
    {
        string normalizedName = EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(authenticationDomainName);
        byte[] encodedName = EncodeAuthenticationDomainName(normalizedName);
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> normalizedServiceParameters =
            EncryptedDnsProvisioningServiceParameter.Normalize(serviceParameters);
        if (requireAlpnServiceParameter && !normalizedServiceParameters.Any(static parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey))
        {
            throw new ArgumentException("OPTION_V6_DNR SvcParams should include the alpn SvcParam unless ALPN preference is explicitly disabled.", nameof(serviceParameters));
        }

        List<IPAddress> normalizedAddresses = NormalizeIpv6Addresses(addresses);
        if (normalizedAddresses.Count == 0 && normalizedServiceParameters.Count != 0)
        {
            throw new ArgumentException("OPTION_V6_DNR with SvcParams must also include IPv6 resolver addresses.", nameof(addresses));
        }

        return new EncryptedDnsDiscoveryDhcpv6Option(
            servicePriority,
            normalizedName,
            encodedName,
            new ReadOnlyCollection<IPAddress>(normalizedAddresses),
            normalizedServiceParameters);
    }

    /// <summary>
    /// Creates OPTION_ORO payload bytes that request OPTION_V6_DNR.
    /// </summary>
    public static byte[] CreateOptionRequestOptionData()
    {
        byte[] encoded = new byte[UInt16FieldOctets];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr);
        return encoded;
    }

    /// <summary>
    /// Gets the RFC 9463 default port for a DNS ALPN identifier when no port SvcParam is present.
    /// </summary>
    public static int GetDefaultPortForAlpn(string alpnProtocol)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(alpnProtocol);
        if (!DnsServiceBindingRecord.TryMapAlpn(alpnProtocol.Trim().ToLowerInvariant(), out DnsServiceBindingProtocol protocol))
        {
            throw new ArgumentException("The ALPN protocol is not a recognized encrypted DNS ALPN identifier.", nameof(alpnProtocol));
        }

        return DnsServiceBindingRecord.GetDefaultPort(protocol);
    }

    /// <summary>
    /// Encodes this option as a DHCPv6 option-code, option-length, and option-data TLV.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[OptionHeaderOctets + OptionLength];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, OptionCode);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(UInt16FieldOctets), OptionLength);

        int offset = OptionHeaderOctets;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), ServicePriority);
        offset += UInt16FieldOctets;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), AuthenticationDomainNameLength);
        offset += UInt16FieldOctets;
        authenticationDomainNameWire.CopyTo(encoded.AsSpan(offset));
        offset += authenticationDomainNameWire.Length;

        if (UsesAdnOnlyMode)
        {
            return encoded;
        }

        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), AddressLength);
        offset += UInt16FieldOctets;
        foreach (IPAddress address in Addresses)
        {
            address.GetAddressBytes().CopyTo(encoded, offset);
            offset += Ipv6AddressOctets;
        }

        foreach (EncryptedDnsProvisioningServiceParameter parameter in ServiceParameters)
        {
            parameter.WriteTo(encoded.AsSpan(offset, parameter.EncodedLength));
            offset += parameter.EncodedLength;
        }

        return encoded;
    }

    /// <summary>
    /// Decodes a single DHCPv6 OPTION_V6_DNR TLV.
    /// </summary>
    public static EncryptedDnsDiscoveryDhcpv6Option Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < OptionHeaderOctets)
        {
            throw new ArgumentException("The DHCPv6 option is shorter than the option header.", nameof(encoded));
        }

        ushort optionCode = BinaryPrimitives.ReadUInt16BigEndian(encoded);
        if (optionCode != EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr)
        {
            throw new ArgumentException("The DHCPv6 option code is not OPTION_V6_DNR.", nameof(encoded));
        }

        ushort optionLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[UInt16FieldOctets..]);
        if (encoded.Length != OptionHeaderOctets + optionLength)
        {
            throw new ArgumentException("The DHCPv6 option length does not match the encoded option size.", nameof(encoded));
        }

        if (optionLength < FixedDataWithoutAddressLengthOctets)
        {
            throw new ArgumentException("The OPTION_V6_DNR option data is shorter than the fixed fields.", nameof(encoded));
        }

        ReadOnlySpan<byte> data = encoded.Slice(OptionHeaderOctets, optionLength);
        ushort servicePriority = BinaryPrimitives.ReadUInt16BigEndian(data);
        ushort authenticationNameLength = BinaryPrimitives.ReadUInt16BigEndian(data[UInt16FieldOctets..]);
        if (data.Length - FixedDataWithoutAddressLengthOctets < authenticationNameLength)
        {
            throw new ArgumentException("The OPTION_V6_DNR ADN Length exceeds the option data.", nameof(encoded));
        }

        int offset = FixedDataWithoutAddressLengthOctets;
        string authenticationDomainName = DecodeAuthenticationDomainName(data.Slice(offset, authenticationNameLength));
        offset += authenticationNameLength;
        if (offset == data.Length)
        {
            return CreateAdnOnly(authenticationDomainName, servicePriority);
        }

        if (data.Length - offset < AddressLengthFieldOctets)
        {
            throw new ArgumentException("The OPTION_V6_DNR option ends inside the Addr Length field.", nameof(encoded));
        }

        ushort addressLength = BinaryPrimitives.ReadUInt16BigEndian(data[offset..]);
        offset += AddressLengthFieldOctets;
        if (addressLength == 0 || addressLength % Ipv6AddressOctets != 0)
        {
            throw new ArgumentException("The OPTION_V6_DNR Addr Length must be a non-zero multiple of 16.", nameof(encoded));
        }

        if (data.Length - offset < addressLength)
        {
            throw new ArgumentException("The OPTION_V6_DNR Addr Length exceeds the option data.", nameof(encoded));
        }

        List<IPAddress> addresses = [];
        int addressEnd = offset + addressLength;
        while (offset < addressEnd)
        {
            IPAddress address = new(data.Slice(offset, Ipv6AddressOctets));
            if (EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
            {
                addresses.Add(address);
            }

            offset += Ipv6AddressOctets;
        }

        if (addresses.Count == 0)
        {
            throw new ArgumentException("The OPTION_V6_DNR option does not contain a usable IPv6 resolver address.", nameof(encoded));
        }

        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters =
            EncryptedDnsProvisioningServiceParameter.DecodeMany(data[offset..]);
        return Create(authenticationDomainName, addresses, servicePriority, serviceParameters, requireAlpnServiceParameter: false);
    }

    /// <summary>
    /// Decodes all OPTION_V6_DNR TLVs from a DHCPv6 option sequence, returning separate resolvers sorted by service priority.
    /// </summary>
    public static IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> DecodeMany(
        ReadOnlySpan<byte> dhcpv6Options,
        bool silentlyDiscardInvalidOptions = true)
    {
        List<EncryptedDnsDiscoveryDhcpv6Option> options = [];
        int offset = 0;
        while (offset < dhcpv6Options.Length)
        {
            if (dhcpv6Options.Length - offset < OptionHeaderOctets)
            {
                if (silentlyDiscardInvalidOptions)
                {
                    break;
                }

                throw new ArgumentException("The DHCPv6 option sequence ends inside an option header.", nameof(dhcpv6Options));
            }

            ushort optionCode = BinaryPrimitives.ReadUInt16BigEndian(dhcpv6Options[offset..]);
            ushort optionLength = BinaryPrimitives.ReadUInt16BigEndian(dhcpv6Options[(offset + UInt16FieldOctets)..]);
            int optionEnd = offset + OptionHeaderOctets + optionLength;
            if (optionEnd > dhcpv6Options.Length)
            {
                if (silentlyDiscardInvalidOptions)
                {
                    break;
                }

                throw new ArgumentException("The DHCPv6 option sequence contains a truncated option.", nameof(dhcpv6Options));
            }

            if (optionCode == EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr)
            {
                try
                {
                    options.Add(Decode(dhcpv6Options.Slice(offset, OptionHeaderOctets + optionLength)));
                }
                catch (ArgumentException) when (silentlyDiscardInvalidOptions)
                {
                    // RFC 9463 requires invalid OPTION_V6_DNR values to be silently discarded.
                }
            }

            offset = optionEnd;
        }

        options.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        return new ReadOnlyCollection<EncryptedDnsDiscoveryDhcpv6Option>(options);
    }

    private static List<IPAddress> NormalizeIpv6Addresses(IEnumerable<IPAddress>? addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        List<IPAddress> normalized = [];
        foreach (IPAddress? address in addresses)
        {
            if (address is null || address.AddressFamily != AddressFamily.InterNetworkV6)
            {
                throw new ArgumentException("OPTION_V6_DNR addresses must be IPv6 addresses.", nameof(addresses));
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
            throw new ArgumentException("The OPTION_V6_DNR authentication-domain-name must be a complete RFC 8415 DNS name.", nameof(encoded));
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
                    throw new ArgumentException("The OPTION_V6_DNR authentication-domain-name contains trailing data after the root label.", nameof(encoded));
                }

                return EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(string.Join(".", labels));
            }

            if (labelLength > MaximumDnsLabelLength || encoded.Length - offset < labelLength)
            {
                throw new ArgumentException("The OPTION_V6_DNR authentication-domain-name contains an invalid DNS label.", nameof(encoded));
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(encoded.Slice(offset, labelLength)));
            offset += labelLength;
        }

        throw new ArgumentException("The OPTION_V6_DNR authentication-domain-name is incomplete.", nameof(encoded));
    }
}
