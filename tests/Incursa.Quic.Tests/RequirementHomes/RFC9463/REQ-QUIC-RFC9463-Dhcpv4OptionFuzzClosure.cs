// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

using Dhcpv4Instance = EncryptedDnsDiscoveryDhcpv4Option.EncryptedDnsDiscoveryDhcpv4Instance;

public sealed class REQ_QUIC_RFC9463_Dhcpv4OptionFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV4DnrContainsLengthAndInstanceData()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance(priority: 7)]);
        byte[] encoded = option.Encode();

        Assert.Equal(option.OptionDataLength, encoded[1]);
        Assert.Equal(option.Instances[0].InstanceDataLength, encoded[2]);
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(3)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0046")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV4DnrUsesCode162()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();

        Assert.Equal(162, encoded[0]);
        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, encoded[0]);
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode([0x12, 0x00]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0047")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LengthFieldMustMatchOptionDataOctets()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        Assert.Equal(encoded.Length - 2, encoded[1]);

        encoded[1]++;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0048")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InstanceDataFieldsStayInWireOrder()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance(priority: 9, address: IPAddress.Parse("192.0.2.77"));
        byte[] encoded = instance.EncodeInstance();
        int addressLengthOffset = 4 + encoded[3];

        Assert.Equal(instance.InstanceDataLength, encoded[0]);
        Assert.Equal(9, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(1)));
        Assert.Equal(instance.AuthenticationDomainNameLength, encoded[3]);
        Assert.Equal(instance.AddressLength, encoded[addressLengthOffset]);
        Assert.True(ContainsSubsequence(encoded, IPAddress.Parse("192.0.2.77").GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0049")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OptionV4DnrRepeatsInstanceDataForMultipleResolvers()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeTwoInstanceOption();

        Assert.Equal(2, decoded.Instances.Count);
        Assert.Equal([IPAddress.Parse("192.0.2.53")], decoded.Instances[0].Addresses);
        Assert.Equal([IPAddress.Parse("192.0.2.54")], decoded.Instances[1].Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0050")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InstanceDataLengthCoversFollowingData()
    {
        Dhcpv4Instance decoded = DecodeSingleInstance();

        Assert.Equal(decoded.EncodedLength - 1, decoded.InstanceDataLength);
        Assert.True(decoded.InstanceDataLength > decoded.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0051")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyInstanceLengthIsAdnLengthPlusThree()
    {
        Dhcpv4Instance instance = Dhcpv4Instance.CreateAdnOnly("resolver.example", servicePriority: 9);

        Assert.True(instance.UsesAdnOnlyMode);
        Assert.Equal(instance.AuthenticationDomainNameLength + 3, instance.InstanceDataLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServicePriorityOrdersDhcpv4Instances()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeTwoInstanceOption();

        Assert.Equal(10, decoded.Instances[0].ServicePriority);
        Assert.Equal(20, decoded.Instances[1].ServicePriority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0053")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnLengthMatchesAuthenticationNameOctets()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();
        byte[] encoded = instance.EncodeInstance();

        Assert.Equal(instance.AuthenticationDomainNameWire.Length, instance.AuthenticationDomainNameLength);
        Assert.Equal(instance.AuthenticationDomainNameLength, encoded[3]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0054")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameCarriesResolverAdn()
    {
        Dhcpv4Instance decoded = DecodeSingleInstance();

        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0055")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthenticationDomainNameUsesRfc8415WireFormat()
    {
        Dhcpv4Instance decoded = DecodeSingleInstance();

        Assert.Equal(
            [8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0],
            decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0056")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthCoversIpv4AddressOctets()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance(address: IPAddress.Parse("192.0.2.53"));

        Assert.Equal(4, instance.AddressLength);
        Assert.Equal(instance.Addresses.Count * 4, instance.AddressLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0057")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressLengthMustBeMultipleOfFour()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        int addressLengthOffset = 6 + encoded[5];
        encoded[addressLengthOffset] = 3;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv4Option.Decode(encoded, silentlyDiscardInvalidInstances: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0058")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv4AddressFieldCarriesResolverAddress()
    {
        IPAddress address = IPAddress.Parse("192.0.2.53");
        Dhcpv4Instance instance = CreatePopulatedInstance(address: address);

        Assert.Equal([address], instance.Addresses);
        Assert.True(ContainsSubsequence(instance.EncodeInstance(), address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0059")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv4AddressFieldAllowsPrivateAndPublicAddresses()
    {
        foreach (IPAddress address in new[] { IPAddress.Parse("10.0.0.53"), IPAddress.Parse("198.51.100.53") })
        {
            Dhcpv4Instance instance = CreatePopulatedInstance(address: address);

            Assert.Equal([address], instance.Addresses);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0060")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsUseRfc9460KeyLengthValueEncoding()
    {
        byte[] encoded = CreatePopulatedInstance().EncodeInstance();
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];

        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0061")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsIncludeAlpn()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.Contains(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.Throws<ArgumentException>(() =>
            Dhcpv4Instance.CreateInstance(
                "resolver.example",
                [IPAddress.Parse("192.0.2.53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0062")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsRejectIpv4Hint()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.DoesNotContain(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv4HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0063")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SvcParamsRejectIpv6Hint()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.DoesNotContain(instance.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0064")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultPortsFollowEncryptedDnsAlpnWhenPortIsAbsent()
    {
        foreach ((string alpn, int expectedPort) in new[] { ("dot", 853), ("doq", 853), ("h2", 443), ("h3", 443) })
        {
            Assert.Equal(expectedPort, EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn(alpn));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0065")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServiceParameterLengthMatchesInstanceLengthFormula()
    {
        Dhcpv4Instance instance = CreatePopulatedInstance();

        Assert.Equal(
            instance.InstanceDataLength - 4 - instance.AuthenticationDomainNameLength - instance.AddressLength,
            instance.ServiceParametersLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyModeOmitsAddressLength()
    {
        Dhcpv4Instance instance = Dhcpv4Instance.CreateAdnOnly("resolver.example");

        Assert.True(instance.UsesAdnOnlyMode);
        Assert.Equal(0, instance.AddressLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0067")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyModeOmitsIpv4Addresses()
    {
        Dhcpv4Instance instance = Dhcpv4Instance.CreateAdnOnly("resolver.example");

        Assert.True(instance.UsesAdnOnlyMode);
        Assert.Empty(instance.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0068")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AdnOnlyModeOmitsSvcParams()
    {
        Dhcpv4Instance instance = Dhcpv4Instance.CreateAdnOnly("resolver.example");

        Assert.True(instance.UsesAdnOnlyMode);
        Assert.Empty(instance.ServiceParameters);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0069")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OversizedOptionUsesRfc3396Concatenation()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = CreateOversizedOption();
        IReadOnlyList<byte[]> segments = option.EncodeRfc3396Segments();

        Assert.True(option.RequiresRfc3396Concatenation);
        Assert.True(segments.Count > 1);
        Assert.All(segments, segment => Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, segment[0]));
        Assert.Throws<InvalidOperationException>(() => option.Encode());
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv4ParameterRequestListIncludesOptionV4Dnr()
    {
        byte[] requestData = EncryptedDnsDiscoveryDhcpv4Option.CreateParameterRequestListData();

        Assert.Equal([EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr], requestData);
        Assert.NotEqual([(byte)EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr], requestData);
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Dhcpv4ClientReceivesMultipleInstanceEntries()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeTwoInstanceOption();

        Assert.Equal(2, decoded.Instances.Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0072")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EachInstanceDataEntryIsSeparateResolver()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeTwoInstanceOption();

        Assert.NotSame(decoded.Instances[0], decoded.Instances[1]);
        Assert.NotEqual(decoded.Instances[0].Addresses[0], decoded.Instances[1].Addresses[0]);
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InstancesAreProcessedByIncreasingServicePriority()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeTwoInstanceOption();

        Assert.Collection(
            decoded.Instances,
            first => Assert.Equal(10, first.ServicePriority),
            second => Assert.Equal(20, second.ServicePriority));
    }

    [Fact]
    [Requirement("RFC9463-S5-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidInstancesAreSilentlyDiscardedByDefault()
    {
        EncryptedDnsDiscoveryDhcpv4Option decoded = DecodeLoopbackMulticastAndValidInstances();

        Dhcpv4Instance instance = Assert.Single(decoded.Instances);
        Assert.Equal([IPAddress.Parse("192.0.2.53")], instance.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0075")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LoopbackAddressesAreSilentlyDiscarded()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.Loopback);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv4Option.Decode(loopback, silentlyDiscardInvalidInstances: false));
        Assert.Single(DecodeLoopbackMulticastAndValidInstances().Instances);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0076")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MulticastAddressesAreSilentlyDiscarded()
    {
        byte[] multicast = CreateEncodedOptionWithRawAddress(IPAddress.Parse("224.0.0.251"));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv4Option.Decode(multicast, silentlyDiscardInvalidInstances: false));
        Assert.Single(DecodeLoopbackMulticastAndValidInstances().Instances);
    }

    private static Dhcpv4Instance DecodeSingleInstance()
    {
        return EncryptedDnsDiscoveryDhcpv4Option.Decode(
            EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode()).Instances[0];
    }

    private static EncryptedDnsDiscoveryDhcpv4Option DecodeTwoInstanceOption()
    {
        EncryptedDnsDiscoveryDhcpv4Option option = EncryptedDnsDiscoveryDhcpv4Option.Create(
            [CreatePopulatedInstance(priority: 20, address: IPAddress.Parse("192.0.2.54")), CreatePopulatedInstance(priority: 10, address: IPAddress.Parse("192.0.2.53"))]);

        return EncryptedDnsDiscoveryDhcpv4Option.Decode(option.Encode());
    }

    private static EncryptedDnsDiscoveryDhcpv4Option DecodeLoopbackMulticastAndValidInstances()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.Loopback);
        byte[] multicast = CreateEncodedOptionWithRawAddress(IPAddress.Parse("224.0.0.251"));
        byte[] valid = EncryptedDnsDiscoveryDhcpv4Option.Create([CreatePopulatedInstance()]).Encode();
        byte optionDataLength = checked((byte)(loopback[1] + multicast[1] + valid[1]));
        byte[] combined = [EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr, optionDataLength, .. loopback.AsSpan(2), .. multicast.AsSpan(2), .. valid.AsSpan(2)];

        return EncryptedDnsDiscoveryDhcpv4Option.Decode(combined);
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
