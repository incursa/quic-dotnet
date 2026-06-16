// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
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
    private const int AttributeHeaderOctets = 4;
    private const int UInt16FieldOctets = 2;
    private const int IpAttributeFixedDataLength = 4;
    private const int Ipv4AddressOctets = 4;
    private const int Ipv6AddressOctets = 16;

    private EncryptedDnsProvisioningAttribute(
        EncryptedDnsProvisioningPayloadType payloadType,
        EncryptedDnsProvisioningAddressFamily addressFamily,
        ushort length,
        ushort servicePriority,
        byte addressCount,
        string authenticationDomainName,
        ReadOnlyCollection<IPAddress> addresses,
        ReadOnlyCollection<string> serviceParameterKeys,
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters,
        bool omitsTrailingFields)
    {
        PayloadType = payloadType;
        AddressFamily = addressFamily;
        Length = length;
        ServicePriority = servicePriority;
        AddressCount = addressCount;
        AuthenticationDomainName = authenticationDomainName;
        Addresses = addresses;
        ServiceParameterKeys = serviceParameterKeys;
        ServiceParameters = serviceParameters;
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
    /// Gets the ENCDNS_IP4 attribute type.
    /// </summary>
    public const ushort Ip4AttributeType = 27;

    /// <summary>
    /// Gets the ENCDNS_IP6 attribute type.
    /// </summary>
    public const ushort Ip6AttributeType = 28;

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
    /// Gets the Service Priority field value. A value of zero is AliasMode and is not valid for RFC 9464 ENCDNS_IP* attributes.
    /// </summary>
    public ushort ServicePriority { get; }

    /// <summary>
    /// Gets the IKEv2 Configuration Payload Attribute Type value.
    /// </summary>
    public ushort AttributeType => AddressFamily == EncryptedDnsProvisioningAddressFamily.Ip4 ? Ip4AttributeType : Ip6AttributeType;

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
    /// Gets RFC 9460 wire-format service parameters that apply to all addresses.
    /// </summary>
    public IReadOnlyList<EncryptedDnsProvisioningServiceParameter> ServiceParameters { get; }

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
            servicePriority: 0,
            addressCount: 0,
            authenticationDomainName: string.Empty,
            new ReadOnlyCollection<IPAddress>([]),
            new ReadOnlyCollection<string>([]),
            new ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter>([]),
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
        IEnumerable<string>? serviceParameterKeys = null,
        ushort servicePriority = 1)
    {
        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters = NormalizeServiceParameterKeys(serviceParameterKeys);
        return CreateAddressListWithServiceParameters(payloadType, addressFamily, authenticationDomainName, addresses, serviceParameters, servicePriority);
    }

    /// <summary>
    /// Creates a populated ENCDNS_IP* attribute with RFC 9460 wire-format service parameters.
    /// </summary>
    public static EncryptedDnsProvisioningAttribute CreateAddressListWithServiceParameters(
        EncryptedDnsProvisioningPayloadType payloadType,
        EncryptedDnsProvisioningAddressFamily addressFamily,
        string authenticationDomainName,
        IEnumerable<IPAddress> addresses,
        IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters,
        ushort servicePriority = 1)
    {
        if (payloadType == EncryptedDnsProvisioningPayloadType.Ack)
        {
            throw new ArgumentException("CFG_ACK ENCDNS_IP* attributes must use zero-length data.", nameof(payloadType));
        }

        if (servicePriority == 0)
        {
            throw new ArgumentException("RFC 9464 ENCDNS_IP* attributes do not support AliasMode service priority zero.", nameof(servicePriority));
        }

        string normalizedName = NormalizeAuthenticationDomainName(authenticationDomainName);
        int authenticationNameLength = Encoding.ASCII.GetByteCount(normalizedName);
        if (authenticationNameLength > byte.MaxValue)
        {
            throw new ArgumentException("The authentication domain name must fit in the one-octet ADN Length field.", nameof(authenticationDomainName));
        }

        List<IPAddress> normalizedAddresses = NormalizeAddresses(addressFamily, addresses);
        if (normalizedAddresses.Count == 0 && payloadType is EncryptedDnsProvisioningPayloadType.Reply or EncryptedDnsProvisioningPayloadType.Set)
        {
            throw new ArgumentException("CFG_REPLY and CFG_SET ENCDNS_IP* attributes must contain at least one address.", nameof(addresses));
        }

        if (normalizedAddresses.Count > byte.MaxValue)
        {
            throw new ArgumentException("The address count must fit in the one-octet Num Addresses field.", nameof(addresses));
        }

        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> normalizedServiceParameters =
            EncryptedDnsProvisioningServiceParameter.Normalize(serviceParameters);
        ReadOnlyCollection<string> normalizedServiceParameterKeys = GetServiceParameterKeys(normalizedServiceParameters);
        int serviceParameterLength = GetServiceParameterLength(normalizedServiceParameters);
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
            servicePriority,
            (byte)normalizedAddresses.Count,
            normalizedName,
            new ReadOnlyCollection<IPAddress>(normalizedAddresses),
            normalizedServiceParameterKeys,
            normalizedServiceParameters,
            omitsTrailingFields: false);
    }

    /// <summary>
    /// Encodes the attribute header and data fields in RFC 9464 wire order.
    /// </summary>
    public byte[] Encode()
    {
        byte[] encoded = new byte[AttributeHeaderOctets + Length];
        BinaryPrimitives.WriteUInt16BigEndian(encoded, AttributeType);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(UInt16FieldOctets), Length);
        if (Length == 0)
        {
            return encoded;
        }

        int offset = AttributeHeaderOctets;
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(offset), ServicePriority);
        offset += UInt16FieldOctets;
        encoded[offset++] = AddressCount;
        encoded[offset++] = checked((byte)Encoding.ASCII.GetByteCount(AuthenticationDomainName));
        foreach (IPAddress address in Addresses)
        {
            byte[] addressBytes = address.GetAddressBytes();
            addressBytes.CopyTo(encoded, offset);
            offset += addressBytes.Length;
        }

        offset += Encoding.ASCII.GetBytes(AuthenticationDomainName, encoded.AsSpan(offset));
        foreach (EncryptedDnsProvisioningServiceParameter parameter in ServiceParameters)
        {
            parameter.WriteTo(encoded.AsSpan(offset, parameter.EncodedLength));
            offset += parameter.EncodedLength;
        }

        return encoded;
    }

    /// <summary>
    /// Decodes an ENCDNS_IP* attribute header and data fields.
    /// </summary>
    public static EncryptedDnsProvisioningAttribute Decode(EncryptedDnsProvisioningPayloadType payloadType, ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < AttributeHeaderOctets)
        {
            throw new ArgumentException("The ENCDNS_IP* attribute is shorter than the IKEv2 attribute header.", nameof(encoded));
        }

        ushort attributeTypeWithReservedBit = BinaryPrimitives.ReadUInt16BigEndian(encoded);
        ushort attributeType = (ushort)(attributeTypeWithReservedBit & 0x7FFF);
        EncryptedDnsProvisioningAddressFamily addressFamily = attributeType switch
        {
            Ip4AttributeType => EncryptedDnsProvisioningAddressFamily.Ip4,
            Ip6AttributeType => EncryptedDnsProvisioningAddressFamily.Ip6,
            _ => throw new ArgumentException("The IKEv2 attribute type is not ENCDNS_IP4 or ENCDNS_IP6.", nameof(encoded)),
        };

        ushort length = BinaryPrimitives.ReadUInt16BigEndian(encoded[UInt16FieldOctets..]);
        if (encoded.Length != AttributeHeaderOctets + length)
        {
            throw new ArgumentException("The ENCDNS_IP* Length field does not match the encoded attribute size.", nameof(encoded));
        }

        if (length == 0)
        {
            return CreateEmpty(payloadType, addressFamily);
        }

        if (length < IpAttributeFixedDataLength)
        {
            throw new ArgumentException("The ENCDNS_IP* attribute data is shorter than the fixed data fields.", nameof(encoded));
        }

        ReadOnlySpan<byte> data = encoded.Slice(AttributeHeaderOctets, length);
        ushort servicePriority = BinaryPrimitives.ReadUInt16BigEndian(data);
        if (servicePriority == 0)
        {
            throw new ArgumentException("RFC 9464 ENCDNS_IP* attributes do not support AliasMode service priority zero.", nameof(encoded));
        }

        byte addressCount = data[2];
        byte authenticationNameLength = data[3];
        if (addressCount == 0 && payloadType is EncryptedDnsProvisioningPayloadType.Reply or EncryptedDnsProvisioningPayloadType.Set)
        {
            throw new ArgumentException("CFG_REPLY and CFG_SET ENCDNS_IP* attributes must not set Num Addresses to zero.", nameof(encoded));
        }

        int addressOctets = addressFamily == EncryptedDnsProvisioningAddressFamily.Ip4 ? Ipv4AddressOctets : Ipv6AddressOctets;
        int addressBytesLength = addressCount * addressOctets;
        if (data.Length - IpAttributeFixedDataLength < addressBytesLength + authenticationNameLength)
        {
            throw new ArgumentException("The ENCDNS_IP* attribute data is shorter than the fields indicated by Num Addresses and ADN Length.", nameof(encoded));
        }

        int offset = IpAttributeFixedDataLength;
        List<IPAddress> addresses = [];
        for (int index = 0; index < addressCount; index++)
        {
            addresses.Add(new IPAddress(data.Slice(offset, addressOctets)));
            offset += addressOctets;
        }

        string authenticationDomainName = authenticationNameLength == 0
            ? string.Empty
            : NormalizeAuthenticationDomainName(Encoding.ASCII.GetString(data.Slice(offset, authenticationNameLength)));
        offset += authenticationNameLength;

        ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters =
            EncryptedDnsProvisioningServiceParameter.DecodeMany(data[offset..]);

        return new EncryptedDnsProvisioningAttribute(
            payloadType,
            addressFamily,
            length,
            servicePriority,
            addressCount,
            authenticationDomainName,
            new ReadOnlyCollection<IPAddress>(addresses),
            GetServiceParameterKeys(serviceParameters),
            serviceParameters,
            omitsTrailingFields: false);
    }

    internal static string NormalizeAuthenticationDomainName(string? authenticationDomainName)
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

    private static ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> NormalizeServiceParameterKeys(IEnumerable<string>? serviceParameterKeys)
    {
        if (serviceParameterKeys is null)
        {
            return new ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter>([]);
        }

        List<EncryptedDnsProvisioningServiceParameter> normalized = [];
        foreach (string? key in serviceParameterKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("SvcParam keys must not be empty.", nameof(serviceParameterKeys));
            }

            normalized.Add(EncryptedDnsProvisioningServiceParameter.FromPresentationKey(key));
        }

        return EncryptedDnsProvisioningServiceParameter.Normalize(normalized);
    }

    private static ReadOnlyCollection<string> GetServiceParameterKeys(IEnumerable<EncryptedDnsProvisioningServiceParameter> serviceParameters)
    {
        List<string> keys = [];
        foreach (EncryptedDnsProvisioningServiceParameter serviceParameter in serviceParameters)
        {
            keys.Add(serviceParameter.Key switch
            {
                EncryptedDnsProvisioningServiceParameter.AlpnKey => "alpn",
                EncryptedDnsProvisioningServiceParameter.PortKey => "port",
                EncryptedDnsProvisioningServiceParameter.Ipv4HintKey => "ipv4hint",
                EncryptedDnsProvisioningServiceParameter.Ipv6HintKey => "ipv6hint",
                _ => "key" + serviceParameter.Key.ToString(System.Globalization.CultureInfo.InvariantCulture),
            });
        }

        return new ReadOnlyCollection<string>(keys);
    }

    private static int GetServiceParameterLength(IEnumerable<EncryptedDnsProvisioningServiceParameter> serviceParameters)
    {
        int length = 0;
        foreach (EncryptedDnsProvisioningServiceParameter parameter in serviceParameters)
        {
            length += parameter.EncodedLength;
        }

        return length;
    }
}
