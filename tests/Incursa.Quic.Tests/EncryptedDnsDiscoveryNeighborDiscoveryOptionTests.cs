// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;
using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsDiscoveryNeighborDiscoveryOptionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0077")]
    [Requirement("REQ-QUIC-RFC9463-0078")]
    [Requirement("REQ-QUIC-RFC9463-0079")]
    [Requirement("REQ-QUIC-RFC9463-0080")]
    [Requirement("REQ-QUIC-RFC9463-0081")]
    [Requirement("REQ-QUIC-RFC9463-0082")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesOptionTypeLengthPriorityLifetimeAndAdnInOrder()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption(priority: 7, lifetime: 900);

        byte[] encoded = option.Encode();

        Assert.Equal(EncryptedDnsDiscoveryOptionCodes.NeighborDiscoveryEncryptedDnsOptionType, encoded[0]);
        Assert.Equal(option.LengthUnits, encoded[1]);
        Assert.Equal(option.EncodedLength, encoded[1] * 8);
        Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(2)));
        Assert.Equal(900u, BinaryPrimitives.ReadUInt32BigEndian(encoded.AsSpan(4)));
        Assert.Equal(option.AuthenticationDomainNameLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0077")]
    [Requirement("REQ-QUIC-RFC9463-0078")]
    [Requirement("REQ-QUIC-RFC9463-0079")]
    [Requirement("REQ-QUIC-RFC9463-0080")]
    [Requirement("REQ-QUIC-RFC9463-0081")]
    [Requirement("REQ-QUIC-RFC9463-0082")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsWrongTypeAndMismatchedLengthUnits()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        encoded[0] = 0;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));

        encoded = CreatePopulatedOption().Encode();
        encoded[1]++;
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0083")]
    [Requirement("REQ-QUIC-RFC9463-0084")]
    [Requirement("REQ-QUIC-RFC9463-0085")]
    [Requirement("REQ-QUIC-RFC9463-0086")]
    [Requirement("REQ-QUIC-RFC9463-0087")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LifetimeModelsInfinityRetirementAndDefaultRecommendation()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption infinite =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example");
        EncryptedDnsDiscoveryNeighborDiscoveryOption retiring =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", lifetime: EncryptedDnsDiscoveryOptionCodes.RetiringLifetime);

        Assert.True(infinite.HasInfiniteLifetime);
        Assert.False(infinite.RetiresAuthenticationDomainName);
        Assert.True(retiring.RetiresAuthenticationDomainName);
        Assert.False(retiring.HasInfiniteLifetime);
        Assert.Equal(1800u, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultLifetimeSeconds(600));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0083")]
    [Requirement("REQ-QUIC-RFC9463-0084")]
    [Requirement("REQ-QUIC-RFC9463-0085")]
    [Requirement("REQ-QUIC-RFC9463-0086")]
    [Requirement("REQ-QUIC-RFC9463-0087")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void FiniteLifetimeIsNeitherInfinityNorRetirement()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption finite =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", lifetime: 300);

        Assert.False(finite.HasInfiniteLifetime);
        Assert.False(finite.RetiresAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0088")]
    [Requirement("REQ-QUIC-RFC9463-0089")]
    [Requirement("REQ-QUIC-RFC9463-0090")]
    [Requirement("REQ-QUIC-RFC9463-0091")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodePreservesRfc8415AuthenticationDomainName()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption decoded =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(CreatePopulatedOption(priority: ushort.MaxValue).Encode());

        Assert.Equal(ushort.MaxValue, decoded.ServicePriority);
        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
        Assert.Equal([8, (byte)'r', (byte)'e', (byte)'s', (byte)'o', (byte)'l', (byte)'v', (byte)'e', (byte)'r', 7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e', 0], decoded.AuthenticationDomainNameWire.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0088")]
    [Requirement("REQ-QUIC-RFC9463-0089")]
    [Requirement("REQ-QUIC-RFC9463-0090")]
    [Requirement("REQ-QUIC-RFC9463-0091")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidAuthenticationDomainNameLength()
    {
        byte[] encoded = EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example").Encode();
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(8), checked((ushort)(BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8)) + 1)));

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0092")]
    [Requirement("REQ-QUIC-RFC9463-0093")]
    [Requirement("REQ-QUIC-RFC9463-0094")]
    [Requirement("REQ-QUIC-RFC9463-0095")]
    [Requirement("REQ-QUIC-RFC9463-0096")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesIpv6AddressLengthAndSharedLifetime()
    {
        IPAddress address = IPAddress.Parse("2001:db8::53");
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption(address: address, lifetime: 600);

        byte[] encoded = option.Encode();
        int addressLengthOffset = 10 + option.AuthenticationDomainNameLength;

        Assert.Equal(16, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(addressLengthOffset)));
        Assert.Equal(600u, option.Lifetime);
        Assert.Equal([address], option.Addresses);
        Assert.True(ContainsSubsequence(encoded, address.GetAddressBytes()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0092")]
    [Requirement("REQ-QUIC-RFC9463-0093")]
    [Requirement("REQ-QUIC-RFC9463-0094")]
    [Requirement("REQ-QUIC-RFC9463-0095")]
    [Requirement("REQ-QUIC-RFC9463-0096")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsInvalidIpv6AddressLength()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        int addressLengthOffset = 10 + BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(8));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(addressLengthOffset), 15);

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0097")]
    [Requirement("REQ-QUIC-RFC9463-0098")]
    [Requirement("REQ-QUIC-RFC9463-0099")]
    [Requirement("REQ-QUIC-RFC9463-0100")]
    [Requirement("REQ-QUIC-RFC9463-0101")]
    [Requirement("REQ-QUIC-RFC9463-0102")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EncodeWritesSvcParamsLengthAndAlpn()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int serviceParameterLengthOffset = 12 + option.AuthenticationDomainNameLength + option.AddressLength;
        int serviceParameterOffset = serviceParameterLengthOffset + 2;

        Assert.Equal(option.ServiceParametersLength, BinaryPrimitives.ReadUInt16BigEndian(encoded.AsSpan(serviceParameterLengthOffset)));
        Assert.Contains(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.AlpnKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv4HintKey);
        Assert.DoesNotContain(option.ServiceParameters, parameter => parameter.Key == EncryptedDnsProvisioningServiceParameter.Ipv6HintKey);
        byte[] expectedAlpnParameter = [0x00, 0x01, 0x00, 0x03, 0x02, (byte)'h', (byte)'3'];
        Assert.True(encoded.AsSpan(serviceParameterOffset, expectedAlpnParameter.Length).SequenceEqual(expectedAlpnParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0097")]
    [Requirement("REQ-QUIC-RFC9463-0098")]
    [Requirement("REQ-QUIC-RFC9463-0099")]
    [Requirement("REQ-QUIC-RFC9463-0100")]
    [Requirement("REQ-QUIC-RFC9463-0101")]
    [Requirement("REQ-QUIC-RFC9463-0102")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CreateRejectsSvcParamsWithoutAlpnOrAddressHints()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                serviceParameters: [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB])]));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.Ipv6HintKey, []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0103")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DefaultPortsFollowEncryptedDnsAlpnWhenPortSvcParamIsAbsent()
    {
        Assert.Equal(853, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn("dot"));
        Assert.Equal(853, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn("doq"));
        Assert.Equal(443, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn("h2"));
        Assert.Equal(443, EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn("h3"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DefaultPortsRejectUnknownAlpn()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.GetDefaultPortForAlpn("smtp"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0104")]
    [Requirement("REQ-QUIC-RFC9463-0105")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AdnOnlyModeOmitsTrailingFieldsAndPadsToEightOctets()
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.CreateAdnOnly("resolver.example", servicePriority: 9);

        byte[] encoded = option.Encode();

        Assert.True(option.UsesAdnOnlyMode);
        Assert.Equal(0, option.EncodedLength % 8);
        Assert.True(option.PaddingLength > 0);
        Assert.False(ContainsSubsequence(encoded, IPAddress.Parse("2001:db8::53").GetAddressBytes()));
        Assert.All(encoded.AsSpan(^option.PaddingLength..).ToArray(), value => Assert.Equal(0, value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0104")]
    [Requirement("REQ-QUIC-RFC9463-0105")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeRejectsNonZeroPadding()
    {
        byte[] encoded = CreatePopulatedOption().Encode();
        encoded[^1] = 1;

        Assert.Throws<ArgumentException>(() => EncryptedDnsDiscoveryNeighborDiscoveryOption.Decode(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0106")]
    [Requirement("RFC9463-S6-2-P2-R01")]
    [Requirement("RFC9463-S6-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DecodeManyReturnsSeparateOptionsSortedByServicePriority()
    {
        byte[] second = CreatePopulatedOption(priority: 20, address: IPAddress.Parse("2001:db8::54")).Encode();
        byte[] first = CreatePopulatedOption(priority: 10, address: IPAddress.Parse("2001:db8::53")).Encode();
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);

        IReadOnlyList<EncryptedDnsDiscoveryNeighborDiscoveryOption> decoded =
            EncryptedDnsDiscoveryNeighborDiscoveryOption.DecodeMany([second, loopback, first]);

        Assert.Equal(2, decoded.Count);
        Assert.Equal(10, decoded[0].ServicePriority);
        Assert.Equal(20, decoded[1].ServicePriority);
        Assert.NotSame(decoded[0], decoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9463-0106")]
    [Requirement("RFC9463-S6-2-P2-R01")]
    [Requirement("RFC9463-S6-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DecodeManyCanRejectInvalidOptionWhenSilentDiscardIsDisabled()
    {
        byte[] loopback = CreateEncodedOptionWithRawAddress(IPAddress.IPv6Loopback);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsDiscoveryNeighborDiscoveryOption.DecodeMany([loopback], silentlyDiscardInvalidOptions: false));
    }

    private static EncryptedDnsDiscoveryNeighborDiscoveryOption CreatePopulatedOption(
        ushort priority = 1,
        IPAddress? address = null,
        uint lifetime = 300)
    {
        return EncryptedDnsDiscoveryNeighborDiscoveryOption.Create(
            "resolver.example",
            [address ?? IPAddress.Parse("2001:db8::53")],
            priority,
            lifetime,
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3'])]);
    }

    private static byte[] CreateEncodedOptionWithRawAddress(IPAddress address)
    {
        EncryptedDnsDiscoveryNeighborDiscoveryOption option = CreatePopulatedOption();
        byte[] encoded = option.Encode();
        int addressOffset = 12 + option.AuthenticationDomainNameLength;
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
