// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

using Dhcpv4Instance = EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance;

public sealed class EncryptedDnsDiscoveryDhcpv4OptionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0045")]
    [Requirement("REQ-QUIC-RFC9463-0046")]
    [Requirement("REQ-QUIC-RFC9463-0047")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesOptionV4DnrCodeLengthAndInstanceData()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance(priority: 7)]);

        byte[] encoded = option.Encode();

        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, encoded[0]);
        Assert.Equal(option.OptionDataLength, encoded[1]);
        Assert.Equal(option.Instances[0].InstanceDataLength, encoded[2]);
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(3)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0045")]
    [Requirement("REQ-QUIC-RFC9463-0046")]
    [Requirement("REQ-QUIC-RFC9463-0047")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsMissingOrMismatchedOptionV4DnrData()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode([0x12, 0x00]));

        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        encoded[1]++;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0048")]
    [Requirement("REQ-QUIC-RFC9463-0050")]
    [Requirement("REQ-QUIC-RFC9463-0052")]
    [Requirement("REQ-QUIC-RFC9463-0053")]
    [Requirement("REQ-QUIC-RFC9463-0054")]
    [Requirement("REQ-QUIC-RFC9463-0055")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InstanceDataPreservesPriorityAndRfc8415AuthenticationDomainName()
    {
        Dhcpv4Instance decoded = EncryptedDnsDiscoveryDhcpv4Option.Decode(
            EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance(priority: ushort.MaxValue)]).Encode()).Instances[0];

        Assert.Equal(ushort.MaxValue, decoded.ServicePriority);
        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
        Assert.Equal(decoded.EncodedLength - 1, decoded.InstanceDataLength);
        Assert.Equal([8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0], decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0048")]
    [Requirement("REQ-QUIC-RFC9463-0050")]
    [Requirement("REQ-QUIC-RFC9463-0052")]
    [Requirement("REQ-QUIC-RFC9463-0053")]
    [Requirement("REQ-QUIC-RFC9463-0054")]
    [Requirement("REQ-QUIC-RFC9463-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidInstanceDataLengthOrAdnLength()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        encoded[2] = 2;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded, silentlyDiscardInvalidInstances: false));

        encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        encoded[5]++;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded, silentlyDiscardInvalidInstances: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0051")]
    [Requirement("REQ-QUIC-RFC9463-0066")]
    [Requirement("REQ-QUIC-RFC9463-0067")]
    [Requirement("REQ-QUIC-RFC9463-0068")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlyInstanceSetsLengthToAdnLengthPlusThreeAndOmitsTrailingFields()
    {
        Dhcpv4Instance instance = Dhcpv4Instance.CreateAdnOnly("resolver.example", servicePriority: 9);

        byte[] encoded = instance.EncodeInstance();

        Assert.True(instance.UsesAdnOnlyMode);
        Assert.Equal(instance.AuthenticationDomainNameLength + 3, instance.InstanceDataLength);
        Assert.Equal(instance.EncodedLength, encoded.Length);
        Assert.False(ContainsSubsequence(encoded, IPAddress.Parse("192.0.2.53").GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0051")]
    [Requirement("REQ-QUIC-RFC9463-0066")]
    [Requirement("REQ-QUIC-RFC9463-0067")]
    [Requirement("REQ-QUIC-RFC9463-0068")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PopulatedInstanceIncludesAddressLengthBeforeIpv4Addresses()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.False(instance.UsesAdnOnlyMode);
        Assert.True(instance.InstanceDataLength > instance.AuthenticationDomainNameLength + 3);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0056")]
    [Requirement("REQ-QUIC-RFC9463-0057")]
    [Requirement("REQ-QUIC-RFC9463-0058")]
    [Requirement("REQ-QUIC-RFC9463-0059")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesIpv4AddressLengthAndAddresses()
    {
        IPAddress address = IPAddress.Parse("192.0.2.53");
        Dhcpv4Instance instance = CreatePopulatedInstance(address: address);

        byte[] encoded = instance.EncodeInstance();

        Assert.Equal(4, instance.AddressLength);
        Assert.Equal([address], instance.Addresses);
        Assert.True(ContainsSubsequence(encoded, address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0056")]
    [Requirement("REQ-QUIC-RFC9463-0057")]
    [Requirement("REQ-QUIC-RFC9463-0058")]
    [Requirement("REQ-QUIC-RFC9463-0059")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidIpv4AddressLength()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        int addressLengthOffset = 6 + encoded[5];
        encoded[addressLengthOffset] = 3;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded, silentlyDiscardInvalidInstances: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0060")]
    [Requirement("REQ-QUIC-RFC9463-0061")]
    [Requirement("REQ-QUIC-RFC9463-0062")]
    [Requirement("REQ-QUIC-RFC9463-0063")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesSvcParamsAndIncludesAlpn()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();
        byte[] encoded = instance.EncodeInstance();

        Assert.Contains(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.DoesNotContain(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.DoesNotContain(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];
        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0060")]
    [Requirement("REQ-QUIC-RFC9463-0061")]
    [Requirement("REQ-QUIC-RFC9463-0062")]
    [Requirement("REQ-QUIC-RFC9463-0063")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CreateRejectsSvcParamsWithoutAlpnOrWithAddressHints()
    {
        Assert.Throws<ArgumentException>(() =>
            Dhcpv4Instance.CreateInstance(
                "resolver.example",
                [IPAddress.Parse("192.0.2.53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv4HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0064")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DefaultPortsFollowEncryptedDnsAlpnWhenPortSvcParamIsAbsent()
    {
        Assert.Equal(853, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("dot"));
        Assert.Equal(853, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("doq"));
        Assert.Equal(443, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("h2"));
        Assert.Equal(443, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("h3"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DefaultPortsRejectUnknownAlpn()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("smtp"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServiceParameterLengthMatchesInstanceDataLengthFormula()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.Equal(
            instance.InstanceDataLength - 4 - instance.AuthenticationDomainNameLength - instance.AddressLength,
            instance.ServiceParametersLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0065")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsTruncatedServiceParameterField()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        encoded[1]--;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded, silentlyDiscardInvalidInstances: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0069")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OversizedOptionUsesRfc3396Segments()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = CreateOversizedOption();

        IReadOnlyList<byte[]> segments = option.EncodeRfc3396Segments();

        Assert.True(option.RequiresRfc3396Concatenation);
        Assert.True(segments.Count > 1);
        Assert.All(segments, segment => Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, segment[0]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0069")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OversizedOptionRejectsSingleOptionEncoding()
    {
        Assert.Throws<InvalidOperationException>(() => CreateOversizedOption().Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0070")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ParameterRequestListDataRequestsOptionV4Dnr()
    {
        Assert.Equal([EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr], EncryptedDnsDiscoveryDhcpv4Option.CreateParameterRequestListData());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0070")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ParameterRequestListDataDoesNotRequestUnknownOrDhcpv6DnrCode()
    {
        byte[] requestData = EncryptedDnsDiscoveryDhcpv4Option.CreateParameterRequestListData();

        Assert.NotEqual([0], requestData);
        Assert.NotEqual([(byte)EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr], requestData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0049")]
    [Requirement("RFC9463-S5-2-P2-R01")]
    [Requirement("REQ-QUIC-RFC9463-0072")]
    [Requirement("RFC9463-S5-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodeReturnsSeparateInstancesSortedByServicePriority()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create(
            [CreatePopulatedInstance(priority: 20, address: IPAddress.Parse("192.0.2.54")), CreatePopulatedInstance(priority: 10, address: IPAddress.Parse("192.0.2.53"))]);

        EncryptedDnsDiscoveryDhcpv4Option decoded = EncryptedDnsDiscoveryDhcpv4Option.Decode(option.Encode());

        Assert.Equal(2, decoded.Instances.Count);
        Assert.Equal(10, decoded.Instances[0].ServicePriority);
        Assert.Equal(20, decoded.Instances[1].ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0049")]
    [Requirement("RFC9463-S5-2-P2-R01")]
    [Requirement("REQ-QUIC-RFC9463-0072")]
    [Requirement("RFC9463-S5-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeIgnoresNonDnrDhcpv4Options()
    {
        byte[] unknown = [0x12, 0x01, 0xFF];
        byte[] dnr = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();

        EncryptedDnsDiscoveryDhcpv4Option decoded = EncryptedDnsDiscoveryDhcpv4Option.Decode([.. unknown, .. dnr]);

        Assert.Single(decoded.Instances);
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P3-R01")]
    [Requirement("REQ-QUIC-RFC9463-0075")]
    [Requirement("REQ-QUIC-RFC9463-0076")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodeSilentlyDiscardsInvalidLoopbackAndMulticastInstances()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.Loopback);
        byte[] multicast = CreateEncodedOptionWithRawAddress(IPAddress.Parse("224.0.0.251"));
        byte[] valid = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        byte optionDataLength = checked((byte)(loopback[1] + multicast[1] + valid[1]));
        byte[] combined = [EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, optionDataLength, .. loopback.AsSpan(2), .. multicast.AsSpan(2), .. valid.AsSpan(2)];

        EncryptedDnsDiscoveryDhcpv4Option decoded = EncryptedDnsDiscoveryDhcpv4Option.Decode(combined);

        Dhcpv4Instance instance = Assert.Single(decoded.Instances);
        Assert.Equal([IPAddress.Parse("192.0.2.53")], instance.Addresses);
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P3-R01")]
    [Requirement("REQ-QUIC-RFC9463-0075")]
    [Requirement("REQ-QUIC-RFC9463-0076")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeCanRejectInvalidInstanceWhenSilentDiscardIsDisabled()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.Loopback);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv4Option.Decode(loopback, silentlyDiscardInvalidInstances: false));
    }

    private static Dhcpv4Instance CreatePopulatedInstance(
        ushort priority = 1,
        IPAddress? address = null)
    {
        return Dhcpv4Instance.CreateInstance(
            "resolver.example",
            [address ?? IPAddress.Parse("192.0.2.53")],
            priority,
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3'])]);
    }

    private static EncryptedDnsDiscoveryDhcpv4Option CreateOversizedOption()
    {
        return EncryptedDnsDiscoveryDhcpv4Option.Create(Enumerable.Range(1, 9).Select(index =>
            CreatePopulatedInstance((ushort)index, IPAddress.Parse($"192.0.2.{index}"))));
    }

    private static byte[] CreateEncodedOptionWithRawAddress(IPAddress address)
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        int addressOffset = 7 + encoded[5];
        address.GetAddressBytes().CopyTo(encoded, addressOffset);
        return encoded;
    }

    private static bool ContainsSubsequence(ReadOnlySpan<byte> source, ReadOnlySpan<byte> candidate)
    {
        for (int offset = 0; offset <= source.Length - candidate.Length; offset++)
        {
            if (source.Slice(offset, candidate.Length).SequenceEqual(candidate))
            {
                return true;
            }
        }

        return false;
    }
}
