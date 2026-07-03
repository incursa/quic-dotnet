// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryDhcpv6OptionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0021")]
    [Requirement("REQ-QUIC-RFC9463-0022")]
    [Requirement("REQ-QUIC-RFC9463-0023")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesDhcpv6OptionCodeLengthAndFieldsInOrder()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption(priority: 7);

        byte[] encoded = option.Encode();

        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.Dhcpv6OptionV6Dnr, BinaryPrimitives.ReadUInt16BigEndian(encoded));
        Assert.Equal(option.OptionLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(4)));
        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0021")]
    [Requirement("REQ-QUIC-RFC9463-0022")]
    [Requirement("REQ-QUIC-RFC9463-0023")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsWrongCodeAndMismatchedOptionLength()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        encoded[1] = 0;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));

        encoded = CreatePopulatedOption().Encode();
        encoded[3]++;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0024")]
    [Requirement("REQ-QUIC-RFC9463-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlyModeSetsLengthToAdnLengthPlusFourAndOmitsTrailingFields()
    {
        EncryptedDnsDiscoveryDhcpv6Option option =
            EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example", servicePriority: 9);

        byte[] encoded = option.Encode();

        Assert.True(option.UsesAdnOnlyMode);
        Assert.Equal(option.AuthenticationDomainNameLength + 4, option.OptionLength);
        Assert.Equal(4 + option.OptionLength, encoded.Length);
        Assert.False(ContainsSubsequence(encoded, IPAddress.Parse("2001:db8::53").GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0024")]
    [Requirement("REQ-QUIC-RFC9463-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonAdnOnlyModeIncludesAddressLengthBeforeAddresses()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();

        Assert.False(option.UsesAdnOnlyMode);
        Assert.True(option.OptionLength > option.AuthenticationDomainNameLength + 4);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0025")]
    [Requirement("REQ-QUIC-RFC9463-0026")]
    [Requirement("REQ-QUIC-RFC9463-0027")]
    [Requirement("REQ-QUIC-RFC9463-0028")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodePreservesServicePriorityAndRfc8415AuthenticationDomainName()
    {
        EncryptedDnsDiscoveryDhcpv6Option decoded =
            EncryptedDnsDiscoveryDhcpv6Option.Decode(CreatePopulatedOption(priority: ushort.MaxValue).Encode());

        Assert.Equal(ushort.MaxValue, decoded.ServicePriority);
        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
        Assert.Equal([8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0], decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0025")]
    [Requirement("REQ-QUIC-RFC9463-0026")]
    [Requirement("REQ-QUIC-RFC9463-0027")]
    [Requirement("REQ-QUIC-RFC9463-0028")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidAuthenticationDomainNameWireLength()
    {
        byte[] encoded = EncryptedDnsDiscoveryDhcpv6Option.CreateAdnOnly("resolver.example").Encode();
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6), checked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6)) + 1)));

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0029")]
    [Requirement("REQ-QUIC-RFC9463-0030")]
    [Requirement("REQ-QUIC-RFC9463-0031")]
    [Requirement("REQ-QUIC-RFC9463-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesIpv6AddressLengthAndAddresses()
    {
        IPAddress address = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption(address: address);

        byte[] encoded = option.Encode();
        int addressLengthOffset = 8 + option.AuthenticationDomainNameLength;

        Assert.Equal(16, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(addressLengthOffset)));
        Assert.Equal([address], option.Addresses);
        Assert.True(ContainsSubsequence(encoded, address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0029")]
    [Requirement("REQ-QUIC-RFC9463-0030")]
    [Requirement("REQ-QUIC-RFC9463-0031")]
    [Requirement("REQ-QUIC-RFC9463-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidIpv6AddressLength()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        int addressLengthOffset = 8 + BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(6));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(addressLengthOffset), 15);

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0033")]
    [Requirement("REQ-QUIC-RFC9463-0034")]
    [Requirement("REQ-QUIC-RFC9463-0035")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesSvcParamsAndIncludesAlpn()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();
        byte[] encoded = option.Encode();

        Assert.Contains(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];
        Assert.True(encoded.AsSpan(^expectedAlpnParameter.Length..).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0033")]
    [Requirement("REQ-QUIC-RFC9463-0034")]
    [Requirement("REQ-QUIC-RFC9463-0035")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CreateRejectsSvcParamsWithoutAlpnOrWithAddressHints()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv6Option.Create(
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0036")]
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
    [Requirement("REQ-QUIC-RFC9463-0036")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DefaultPortsRejectUnknownAlpn()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.GetDefaultPortForAlpn("smtp"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0037")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServiceParameterLengthMatchesOptionLengthFormula()
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();

        Assert.Equal(
            option.OptionLength - 6 - option.AuthenticationDomainNameLength - option.AddressLength,
            option.ServiceParametersLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsTruncatedServiceParameterField()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        Array.Resize(ref encoded, encoded.Length - 1);
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(2), checked((ushort)(encoded.Length - 4)));

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryDhcpv6Option.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0039")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OptionRequestOptionDataRequestsOptionV6Dnr()
    {
        Assert.Equal([0x00, 0x90], EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0039")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OptionRequestOptionDataDoesNotRequestUnknownOrDhcpv4DnrCode()
    {
        byte[] optionRequestData = EncryptedDnsDiscoveryDhcpv6Option.CreateOptionRequestOptionData();

        Assert.NotEqual([0x00, 0x00], optionRequestData);
        Assert.NotEqual([0x00, EncryptedDnsDiscoveryOptionCodes.Dhcpv4OptionV4Dnr], optionRequestData);
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P2-R01")]
    [Requirement("REQ-QUIC-RFC9463-0041")]
    [Requirement("RFC9463-S4-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodeManyReturnsSeparateResolversSortedByServicePriority()
    {
        byte[] second = CreatePopulatedOption(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();
        byte[] first = CreatePopulatedOption(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();

        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded =
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. second, .. first]);

        Assert.Equal(2, decoded.Count);
        Assert.Equal(10, decoded[0].ServicePriority);
        Assert.Equal(20, decoded[1].ServicePriority);
        Assert.NotSame(decoded[0], decoded[1]);
    }

    [Fact]
    [Requirement("RFC9463-S4-2-P2-R01")]
    [Requirement("REQ-QUIC-RFC9463-0041")]
    [Requirement("RFC9463-S4-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeManyIgnoresNonDnrOptions()
    {
        byte[] unknown = [0x12, 0x34, 0x00, 0x01, 0xFF];
        byte[] dnr = CreatePopulatedOption().Encode();

        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded =
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. unknown, .. dnr]);

        Assert.Single(decoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0043")]
    [Requirement("RFC9463-S4-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodeManySilentlyDiscardsInvalidDnrAndLoopbackAddresses()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);
        byte[] valid = CreatePopulatedOption(address: IPAddress.Parse("2001:db8::53")).Encode();

        IReadOnlyList<EncryptedDnsDiscoveryDhcpv6Option> decoded =
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany([.. loopback, .. valid]);

        EncryptedDnsDiscoveryDhcpv6Option option = Assert.Single(decoded);
        Assert.Equal([IPAddress.Parse("2001:db8::53")], option.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0043")]
    [Requirement("RFC9463-S4-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeManyCanRejectInvalidDnrWhenSilentDiscardIsDisabled()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryDhcpv6Option.DecodeMany(loopback, silentlyDiscardInvalidOptions: false));
    }

    private static EncryptedDnsDiscoveryDhcpv6Option CreatePopulatedOption(
        ushort priority = 1,
        IPAddress? address = null)
    {
        return EncryptedDnsDiscoveryDhcpv6Option.Create(
            "resolver.example",
            [address ?? IPAddress.Parse("2001:db8::53")],
            priority,
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3'])]);
    }

    private static byte[] CreateEncodedOptionWithRawAddress(IPAddress address)
    {
        EncryptedDnsDiscoveryDhcpv6Option option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int addressOffset = 10 + option.AuthenticationDomainNameLength;
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
