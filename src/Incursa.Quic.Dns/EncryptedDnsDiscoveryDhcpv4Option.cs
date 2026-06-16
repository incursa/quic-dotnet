// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Dns;

/// <summary>
/// RFC 9463 DHCPv4 OPTION_V4_DNR wire-format helper.
/// </summary>
public sealed class EncryptedDnsDiscoveryDhcpv4Option
{
    private const int OptionHeaderOctets = 2;
    private const int InstanceLengthFieldOctets = 1;
    private const int FixedInstanceDataOctets = 3;
    private const int AddressLengthFieldOctets = 1;
    private const int Ipv4AddressOctets = 4;

    private EncryptedDnsDiscoveryDhcpv4Option(ReadOnlyCollection<EncryptedDnsDiscoveryDhcpv4Instance> instances)
    {
        Instances = instances;
    }

    /// <summary>
    /// Gets the DHCPv4 option tag for OPTION_V4_DNR.
    /// </summary>
    public byte OptionCode => EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr;

    /// <summary>
    /// Gets the DNR Instance Data entries sorted by service priority.
    /// </summary>
    public IReadOnlyList<EncryptedDnsDiscoveryDhcpv4Instance> Instances { get; }

    /// <summary>
    /// Gets the combined OPTION_V4_DNR option data length.
    /// </summary>
    public int OptionDataLength => Instances.Sum(static instance => instance.EncodedLength);

    /// <summary>
    /// Gets a value indicating whether RFC 3396 concatenation is required for a DHCPv4 option encoding.
    /// </summary>
    public bool RequiresRfc3396Concatenation => OptionDataLength > byte.MaxValue;

    /// <summary>
    /// Creates a DHCPv4 OPTION_V4_DNR model from one or more DNR instance data entries.
    /// </summary>
    public static EncryptedDnsDiscoveryDhcpv4Option Create(IEnumerable<EncryptedDnsDiscoveryDhcpv4Instance> instances)
    {
        ArgumentNullException.ThrowIfNull(instances);

        List<EncryptedDnsDiscoveryDhcpv4Instance> normalized = [];
        foreach (EncryptedDnsDiscoveryDhcpv4Instance? instance in instances)
        {
            ArgumentNullException.ThrowIfNull(instance);
            normalized.Add(instance);
        }

        if (normalized.Count == 0)
        {
            throw new ArgumentException("OPTION_V4_DNR must contain at least one DNR Instance Data entry.", nameof(instances));
        }

        normalized.Sort(static (left, right) => left.ServicePriority.CompareTo(right.ServicePriority));
        return new EncryptedDnsDiscoveryDhcpv4Option(new ReadOnlyCollection<EncryptedDnsDiscoveryDhcpv4Instance>(normalized));
    }

    /// <summary>
    /// Creates Parameter Request List payload bytes that request OPTION_V4_DNR.
    /// </summary>
    public static byte[] CreateParameterRequestListData() => [EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr];

    /// <summary>
    /// Encodes OPTION_V4_DNR as a single DHCPv4 option.
    /// </summary>
    public byte[] Encode()
    {
        if (RequiresRfc3396Concatenation)
        {
            throw new InvalidOperationException("OPTION_V4_DNR exceeds 255 octets and must be encoded with RFC 3396 concatenation.");
        }

        byte[] optionData = EncodeOptionData();
        byte[] encoded = new byte[OptionHeaderOctets + optionData.Length];
        encoded[0] = OptionCode;
        encoded[1] = checked((byte)optionData.Length);
        optionData.CopyTo(encoded.AsSpan(OptionHeaderOctets));
        return encoded;
    }

    /// <summary>
    /// Encodes OPTION_V4_DNR using RFC 3396 option concatenation when the option data exceeds 255 octets.
    /// </summary>
    public IReadOnlyList<byte[]> EncodeRfc3396Segments()
    {
        byte[] optionData = EncodeOptionData();
        List<byte[]> segments = [];
        int offset = 0;
        while (offset < optionData.Length)
        {
            int length = Math.Min(byte.MaxValue, optionData.Length - offset);
            byte[] segment = new byte[OptionHeaderOctets + length];
            segment[0] = OptionCode;
            segment[1] = checked((byte)length);
            optionData.AsSpan(offset, length).CopyTo(segment.AsSpan(OptionHeaderOctets));
            segments.Add(segment);
            offset += length;
        }

        return new ReadOnlyCollection<byte[]>(segments);
    }

    /// <summary>
    /// Decodes one or more OPTION_V4_DNR DHCPv4 option TLVs, including RFC 3396 concatenated segments.
    /// </summary>
    public static EncryptedDnsDiscoveryDhcpv4Option Decode(
        ReadOnlySpan<byte> encodedOptions,
        bool silentlyDiscardInvalidInstances = true)
    {
        List<byte> optionData = [];
        int offset = 0;
        while (offset < encodedOptions.Length)
        {
            if (encodedOptions.Length - offset < OptionHeaderOctets)
            {
                throw new ArgumentException("The DHCPv4 option sequence ends inside an option header.", nameof(encodedOptions));
            }

            byte optionCode = encodedOptions[offset++];
            byte length = encodedOptions[offset++];
            if (encodedOptions.Length - offset < length)
            {
                throw new ArgumentException("The DHCPv4 option length exceeds the encoded option sequence.", nameof(encodedOptions));
            }

            if (optionCode == EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr)
            {
                optionData.AddRange(encodedOptions.Slice(offset, length).ToArray());
            }

            offset += length;
        }

        if (optionData.Count == 0)
        {
            throw new ArgumentException("No OPTION_V4_DNR option data was present.", nameof(encodedOptions));
        }

        List<EncryptedDnsDiscoveryDhcpv4Instance> instances = [];
        byte[] optionDataArray = [.. optionData];
        ReadOnlySpan<byte> data = optionDataArray;
        offset = 0;
        while (offset < data.Length)
        {
            try
            {
                EncryptedDnsDiscoveryDhcpv4Instance instance =
                    EncryptedDnsDiscoveryDhcpv4Instance.DecodeInstance(data[offset..], out int bytesConsumed);
                instances.Add(instance);
                offset += bytesConsumed;
            }
            catch (ArgumentException) when (silentlyDiscardInvalidInstances)
            {
                if (data.Length - offset < InstanceLengthFieldOctets)
                {
                    break;
                }

                int bytesToSkip = InstanceLengthFieldOctets + data[offset];
                if (bytesToSkip <= InstanceLengthFieldOctets || data.Length - offset < bytesToSkip)
                {
                    break;
                }

                offset += bytesToSkip;
            }
        }

        return Create(instances);
    }

    private byte[] EncodeOptionData()
    {
        byte[] optionData = new byte[OptionDataLength];
        int offset = 0;
        foreach (EncryptedDnsDiscoveryDhcpv4Instance instance in Instances)
        {
            instance.EncodeInstance().CopyTo(optionData.AsSpan(offset));
            offset += instance.EncodedLength;
        }

        return optionData;
    }

    /// <summary>
    /// One RFC 9463 DHCPv4 DNR Instance Data entry.
    /// </summary>
    public sealed class EncryptedDnsDiscoveryDhcpv4Instance
    {
        private const int ServicePriorityWireOffset = 1;
        private const int AuthenticationDomainNameLengthWireOffset = 3;
        private const int AuthenticationDomainNameWireOffset = 4;
        private const int AuthenticationNameLengthDataOffset = 2;
        private const int AuthenticationDomainNameDataOffset = 3;
        private const int MaximumDnsLabelLength = 63;

        private readonly byte[] authenticationDomainNameWire;

        private EncryptedDnsDiscoveryDhcpv4Instance(
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
        /// Gets the DNR Instance Data Length field value.
        /// </summary>
        public byte InstanceDataLength => checked((byte)(
            FixedInstanceDataOctets
            + AuthenticationDomainNameLength
            + (UsesAdnOnlyMode ? 0 : AddressLengthFieldOctets + AddressLength + ServiceParametersLength)));

        /// <summary>
        /// Gets the encoded DNR Instance Data size including the length field.
        /// </summary>
        public int EncodedLength => InstanceLengthFieldOctets + InstanceDataLength;

        /// <summary>
        /// Gets the 16-bit service priority.
        /// </summary>
        public ushort ServicePriority { get; }

        /// <summary>
        /// Gets the normalized authentication domain name.
        /// </summary>
        public string AuthenticationDomainName { get; }

        /// <summary>
        /// Gets the RFC 8415 DNS wire format authentication domain name.
        /// </summary>
        public ReadOnlyMemory<byte> AuthenticationDomainNameWire => authenticationDomainNameWire;

        /// <summary>
        /// Gets the ADN Length field value.
        /// </summary>
        public byte AuthenticationDomainNameLength => checked((byte)authenticationDomainNameWire.Length);

        /// <summary>
        /// Gets usable IPv4 resolver addresses.
        /// </summary>
        public IReadOnlyList<IPAddress> Addresses { get; }

        /// <summary>
        /// Gets the Addr Length field value.
        /// </summary>
        public byte AddressLength => checked((byte)(Addresses.Count * Ipv4AddressOctets));

        /// <summary>
        /// Gets RFC 9460 SvcParams attached to the instance.
        /// </summary>
        public IReadOnlyList<EncryptedDnsProvisioningServiceParameter> ServiceParameters { get; }

        /// <summary>
        /// Gets the service parameter field length computed from DNR Instance Data Length.
        /// </summary>
        public byte ServiceParametersLength => checked((byte)ServiceParameters.Sum(static parameter => parameter.EncodedLength));

        /// <summary>
        /// Gets a value indicating whether this instance omits Addr Length, IPv4 addresses, and SvcParams.
        /// </summary>
        public bool UsesAdnOnlyMode => Addresses.Count == 0 && ServiceParameters.Count == 0;

        /// <summary>
        /// Creates an ADN-only DHCPv4 DNR instance.
        /// </summary>
        public static EncryptedDnsDiscoveryDhcpv4Instance CreateAdnOnly(
            string authenticationDomainName,
            ushort servicePriority = 0)
        {
            return CreateInstance(
                authenticationDomainName,
                addresses: [],
                servicePriority,
                serviceParameters: [],
                requireAlpnServiceParameter: false);
        }

        /// <summary>
        /// Creates a populated DHCPv4 DNR instance.
        /// </summary>
        public static EncryptedDnsDiscoveryDhcpv4Instance CreateInstance(
            string authenticationDomainName,
            IEnumerable<IPAddress> addresses,
            ushort servicePriority = 0,
            IEnumerable<EncryptedDnsProvisioningServiceParameter>? serviceParameters = null,
            bool requireAlpnServiceParameter = true)
        {
            string normalizedName = EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(authenticationDomainName);
            byte[] encodedName = EncodeAuthenticationDomainName(normalizedName);
            if (encodedName.Length > byte.MaxValue)
            {
                throw new ArgumentException("The OPTION_V4_DNR ADN Length must fit in one octet.", nameof(authenticationDomainName));
            }

            ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> normalizedServiceParameters =
                EncryptedDnsProvisioningServiceParameter.Normalize(serviceParameters);
            if (requireAlpnServiceParameter && !normalizedServiceParameters.Any(static parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey))
            {
                throw new ArgumentException("OPTION_V4_DNR SvcParams should include the alpn SvcParam unless ALPN preference is explicitly disabled.", nameof(serviceParameters));
            }

            List<IPAddress> normalizedAddresses = NormalizeIpv4Addresses(addresses);
            if (normalizedAddresses.Count == 0 && normalizedServiceParameters.Count != 0)
            {
                throw new ArgumentException("OPTION_V4_DNR with SvcParams must also include IPv4 resolver addresses.", nameof(addresses));
            }

            return new EncryptedDnsDiscoveryDhcpv4Instance(
                servicePriority,
                normalizedName,
                encodedName,
                new ReadOnlyCollection<IPAddress>(normalizedAddresses),
                normalizedServiceParameters);
        }

        /// <summary>
        /// Encodes this DNR Instance Data entry.
        /// </summary>
        public byte[] EncodeInstance()
        {
            byte[] encoded = new byte[EncodedLength];
            encoded[0] = InstanceDataLength;
            BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(ServicePriorityWireOffset), ServicePriority);
            encoded[AuthenticationDomainNameLengthWireOffset] = AuthenticationDomainNameLength;
            authenticationDomainNameWire.CopyTo(encoded.AsSpan(AuthenticationDomainNameWireOffset));
            if (UsesAdnOnlyMode)
            {
                return encoded;
            }

            int offset = AuthenticationDomainNameWireOffset + authenticationDomainNameWire.Length;
            encoded[offset++] = AddressLength;
            foreach (IPAddress address in Addresses)
            {
                address.GetAddressBytes().CopyTo(encoded, offset);
                offset += Ipv4AddressOctets;
            }

            foreach (EncryptedDnsProvisioningServiceParameter parameter in ServiceParameters)
            {
                parameter.WriteTo(encoded.AsSpan(offset, parameter.EncodedLength));
                offset += parameter.EncodedLength;
            }

            return encoded;
        }

        internal static EncryptedDnsDiscoveryDhcpv4Instance DecodeInstance(ReadOnlySpan<byte> encoded, out int bytesConsumed)
        {
            bytesConsumed = 0;
            if (encoded.Length < InstanceLengthFieldOctets + FixedInstanceDataOctets)
            {
                throw new ArgumentException("The DNR Instance Data entry is shorter than the fixed fields.", nameof(encoded));
            }

            byte instanceLength = encoded[0];
            if (instanceLength < FixedInstanceDataOctets || encoded.Length - InstanceLengthFieldOctets < instanceLength)
            {
                throw new ArgumentException("The DNR Instance Data Length field exceeds the encoded data.", nameof(encoded));
            }

            ReadOnlySpan<byte> data = encoded.Slice(InstanceLengthFieldOctets, instanceLength);
            ushort servicePriority = BinaryPrimitives.ReadUInt16BigEndian(data);
            byte authenticationNameLength = data[AuthenticationNameLengthDataOffset];
            if (data.Length - FixedInstanceDataOctets < authenticationNameLength)
            {
                throw new ArgumentException("The DNR Instance Data ADN Length exceeds the instance data.", nameof(encoded));
            }

            int offset = AuthenticationDomainNameDataOffset;
            string authenticationDomainName = DecodeAuthenticationDomainName(data.Slice(offset, authenticationNameLength));
            offset += authenticationNameLength;
            bytesConsumed = InstanceLengthFieldOctets + instanceLength;
            if (offset == data.Length)
            {
                return CreateAdnOnly(authenticationDomainName, servicePriority);
            }

            if (data.Length - offset < AddressLengthFieldOctets)
            {
                throw new ArgumentException("The DNR Instance Data ends inside the Addr Length field.", nameof(encoded));
            }

            byte addressLength = data[offset++];
            if (addressLength == 0 || addressLength % Ipv4AddressOctets != 0)
            {
                throw new ArgumentException("The OPTION_V4_DNR Addr Length must be a non-zero multiple of 4.", nameof(encoded));
            }

            if (data.Length - offset < addressLength)
            {
                throw new ArgumentException("The OPTION_V4_DNR Addr Length exceeds the instance data.", nameof(encoded));
            }

            List<IPAddress> addresses = [];
            int addressEnd = offset + addressLength;
            while (offset < addressEnd)
            {
                IPAddress address = new(data.Slice(offset, Ipv4AddressOctets));
                if (EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
                {
                    addresses.Add(address);
                }

                offset += Ipv4AddressOctets;
            }

            if (addresses.Count == 0)
            {
                throw new ArgumentException("The OPTION_V4_DNR instance does not contain a usable IPv4 resolver address.", nameof(encoded));
            }

            ReadOnlyCollection<EncryptedDnsProvisioningServiceParameter> serviceParameters =
                EncryptedDnsProvisioningServiceParameter.DecodeMany(data[offset..]);
            return CreateInstance(authenticationDomainName, addresses, servicePriority, serviceParameters, requireAlpnServiceParameter: false);
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
                throw new ArgumentException("The OPTION_V4_DNR authentication-domain-name must be a complete RFC 8415 DNS name.", nameof(encoded));
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
                        throw new ArgumentException("The OPTION_V4_DNR authentication-domain-name contains trailing data after the root label.", nameof(encoded));
                    }

                    return EncryptedDnsProvisioningAttribute.NormalizeAuthenticationDomainName(string.Join(".", labels));
                }

                if (labelLength > MaximumDnsLabelLength || encoded.Length - offset < labelLength)
                {
                    throw new ArgumentException("The OPTION_V4_DNR authentication-domain-name contains an invalid DNS label.", nameof(encoded));
                }

                labels.Add(System.Text.Encoding.ASCII.GetString(encoded.Slice(offset, labelLength)));
                offset += labelLength;
            }

            throw new ArgumentException("The OPTION_V4_DNR authentication-domain-name is incomplete.", nameof(encoded));
        }

        private static List<IPAddress> NormalizeIpv4Addresses(IEnumerable<IPAddress>? addresses)
        {
            ArgumentNullException.ThrowIfNull(addresses);

            List<IPAddress> normalized = [];
            foreach (IPAddress? address in addresses)
            {
                if (address is null || address.AddressFamily != AddressFamily.InterNetwork)
                {
                    throw new ArgumentException("OPTION_V4_DNR addresses must be IPv4 addresses.", nameof(addresses));
                }

                if (EncryptedDnsDiscoveryOption.IsUsableResolverAddress(address))
                {
                    normalized.Add(address);
                }
            }

            return normalized;
        }
    }
}
