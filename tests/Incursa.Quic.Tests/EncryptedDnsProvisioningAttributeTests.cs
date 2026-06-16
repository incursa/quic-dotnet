// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsProvisioningAttributeTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0002")]
    [Requirement("REQ-QUIC-RFC9464-0003")]
    [Requirement("REQ-QUIC-RFC9464-0023")]
    [Requirement("REQ-QUIC-RFC9464-0024")]
    [Requirement("REQ-QUIC-RFC9464-0035")]
    [Requirement("REQ-QUIC-RFC9464-0036")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReservedBitPolicyIgnoresReceiptAndClearsOutboundAttributes()
    {
        EncryptedDnsProvisioningAttribute ipAttribute = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningDigestInfoAttribute digestAttribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1]);

        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: true));
        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: false));
        Assert.False(ipAttribute.ReservedBitSet);
        Assert.False(digestAttribute.ReservedBitSet);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0002")]
    [Requirement("REQ-QUIC-RFC9464-0023")]
    [Requirement("REQ-QUIC-RFC9464-0035")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReservedBitReceiptPolicyDoesNotRejectEitherReservedBitValue()
    {
        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: true));
        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0003")]
    [Requirement("REQ-QUIC-RFC9464-0024")]
    [Requirement("REQ-QUIC-RFC9464-0036")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OutboundAttributesDoNotSetReservedBit()
    {
        EncryptedDnsProvisioningAttribute ipAttribute = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningDigestInfoAttribute digestAttribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1]);

        Assert.False(ipAttribute.ReservedBitSet);
        Assert.False(digestAttribute.ReservedBitSet);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0004")]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [Requirement("REQ-QUIC-RFC9464-0008")]
    [Requirement("REQ-QUIC-RFC9464-0013")]
    [Requirement("REQ-QUIC-RFC9464-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Ip4AttributeComputesTwoOctetLengthFromAdnAddressAndServiceParameterBytes()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "Resolver.Example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("198.51.100.53")],
            ["alpn"]);

        Assert.Equal(2, EncryptedDnsProvisioningAttribute.LengthFieldOctets);
        Assert.Equal(1, EncryptedDnsProvisioningAttribute.AuthenticationDomainNameLengthFieldOctets);
        Assert.Equal(4 + "resolver.example.".Length + (2 * 4) + "alpn".Length, attribute.Length);
        Assert.Equal(2, attribute.AddressCount);
        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
        Assert.False(attribute.OmitsTrailingFields);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0004")]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeLengthIsNotSignedOrWidened()
    {
        Assert.Equal(typeof(ushort), typeof(EncryptedDnsProvisioningAttribute).GetProperty(nameof(EncryptedDnsProvisioningAttribute.Length))?.PropertyType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Ip4AttributeRejectsLengthThatDoesNotFitTwoOctets()
    {
        string oversizedServiceParameter = new('a', ushort.MaxValue);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example",
                [IPAddress.Parse("192.0.2.53")],
                [oversizedServiceParameter]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0004")]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [Requirement("REQ-QUIC-RFC9464-0009")]
    [Requirement("REQ-QUIC-RFC9464-0013")]
    [Requirement("REQ-QUIC-RFC9464-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Ip6AttributeComputesTwoOctetLengthFromAdnAddressAndServiceParameterBytes()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Set,
            EncryptedDnsProvisioningAddressFamily.Ip6,
            "resolver.example.",
            [IPAddress.Parse("2001:db8::53")],
            ["port"]);

        Assert.Equal(4 + "resolver.example.".Length + 16 + "port".Length, attribute.Length);
        Assert.Equal(1, attribute.AddressCount);
        Assert.Equal([IPAddress.Parse("2001:db8::53")], attribute.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Ip6AttributeRejectsLengthThatDoesNotFitTwoOctets()
    {
        string oversizedServiceParameter = new('a', ushort.MaxValue);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip6,
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                [oversizedServiceParameter]));
    }

    [Theory]
    [InlineData(EncryptedDnsProvisioningPayloadType.Request)]
    [InlineData(EncryptedDnsProvisioningPayloadType.Ack)]
    [Requirement("REQ-QUIC-RFC9464-0006")]
    [Requirement("REQ-QUIC-RFC9464-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EmptyIpAttributeUsesZeroLengthAndOmitsTrailingFields(EncryptedDnsProvisioningPayloadType payloadType)
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateEmpty(
            payloadType,
            EncryptedDnsProvisioningAddressFamily.Ip6);

        Assert.Equal(0, attribute.Length);
        Assert.Equal(0, attribute.AddressCount);
        Assert.Empty(attribute.AuthenticationDomainName);
        Assert.Empty(attribute.Addresses);
        Assert.True(attribute.OmitsTrailingFields);
    }

    [Theory]
    [InlineData(EncryptedDnsProvisioningPayloadType.Reply)]
    [InlineData(EncryptedDnsProvisioningPayloadType.Set)]
    [Requirement("REQ-QUIC-RFC9464-0006")]
    [Requirement("REQ-QUIC-RFC9464-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EmptyIpAttributeRejectsReplyAndSetPayloads(EncryptedDnsProvisioningPayloadType payloadType)
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateEmpty(payloadType, EncryptedDnsProvisioningAddressFamily.Ip4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0014")]
    [Requirement("REQ-QUIC-RFC9464-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsMismatchedAddressFamily()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")]));
    }

    [Theory]
    [InlineData("resolver..example")]
    [InlineData("resolver.example\r")]
    [InlineData("resolver.example\0")]
    [InlineData("192.0.2.53")]
    [Requirement("REQ-QUIC-RFC9464-0016")]
    [Requirement("REQ-QUIC-RFC9464-0017")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsInvalidAuthenticationDomainNames(string authenticationDomainName)
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                authenticationDomainName,
                [IPAddress.Parse("192.0.2.53")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsAuthenticationDomainNameThatDoesNotFitOneOctetLength()
    {
        string longLabel = new('a', 63);
        string tooLongName = $"{longLabel}.{longLabel}.{longLabel}.{longLabel}.example";

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                tooLongName,
                [IPAddress.Parse("192.0.2.53")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0016")]
    [Requirement("REQ-QUIC-RFC9464-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpAttributeAcceptsFullyQualifiedALabelAuthenticationDomainName()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "Resolver.Example.",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsAddressHintServiceParameters()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip6,
                "resolver.example",
                [IPAddress.Parse("2001:db8::53")],
                ["ipv6hint"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0019")]
    [Requirement("REQ-QUIC-RFC9464-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpAttributePreservesNonHintServiceParameterKeysForAllAddresses()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip6,
            "resolver.example",
            [IPAddress.Parse("2001:db8::53"), IPAddress.Parse("2001:db8::54")],
            ["alpn", "port"]);

        Assert.Equal(["alpn", "port"], attribute.ServiceParameterKeys);
        Assert.Equal(2, attribute.Addresses.Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsEmptyServiceParameterKeyForSharedAttributeParameters()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example",
                [IPAddress.Parse("192.0.2.53")],
                [""]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0027")]
    [Requirement("REQ-QUIC-RFC9464-0029")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoRequestComputesLengthAndHashAlgorithmCount()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2, 4]);

        Assert.Equal(29, EncryptedDnsProvisioningDigestInfoAttribute.AttributeType);
        Assert.Equal(2 + (2 * 3), attribute.Length);
        Assert.Equal(3, attribute.HashAlgorithmCount);
        Assert.Equal(0, attribute.AuthenticationDomainNameLength);
        Assert.Equal([1, 2, 4], attribute.HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoAttributeTypeIsTwentyNine()
    {
        Assert.Equal(29, EncryptedDnsProvisioningDigestInfoAttribute.AttributeType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0025")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoAttributeTypeIsNotAnIpAttributeTypePlaceholder()
    {
        Assert.NotEqual(0, EncryptedDnsProvisioningDigestInfoAttribute.AttributeType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoLengthIsTwoOctetUnsignedValue()
    {
        Assert.Equal(typeof(ushort), typeof(EncryptedDnsProvisioningDigestInfoAttribute).GetProperty(nameof(EncryptedDnsProvisioningDigestInfoAttribute.Length))?.PropertyType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoLengthIsNotSignedOrWidened()
    {
        Assert.NotEqual(typeof(int), typeof(EncryptedDnsProvisioningDigestInfoAttribute).GetProperty(nameof(EncryptedDnsProvisioningDigestInfoAttribute.Length))?.PropertyType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoLengthFormulaRejectsMissingHashAlgorithms()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0028")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoHashAlgorithmCountReflectsIdentifierCount()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);

        Assert.Equal(2, attribute.HashAlgorithmCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0028")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoHashAlgorithmCountRejectsMissingIdentifiers()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0029")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoDerivedHashAlgorithmCountRejectsMissingLengthContribution()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoRequestUsesZeroAdnLength()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1]);

        Assert.Equal(0, attribute.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestDoesNotCarryAuthenticationDomainNameLength()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1]);

        Assert.NotEqual(1, attribute.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0031")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoRequestPreservesSupportedHashAlgorithmIdentifiers()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2, 4]);

        Assert.Equal([1, 2, 4], attribute.HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0031")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestRejectsMissingHashAlgorithmIdentifiers()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0033")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoRequestLengthContainsNoPaddingBetweenIdentifiers()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2, 4]);

        Assert.Equal(8, attribute.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0033")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestLengthDoesNotIncludeIdentifierPadding()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);

        Assert.NotEqual(7, attribute.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0025")]
    [Requirement("REQ-QUIC-RFC9464-0026")]
    [Requirement("REQ-QUIC-RFC9464-0027")]
    [Requirement("REQ-QUIC-RFC9464-0028")]
    [Requirement("REQ-QUIC-RFC9464-0029")]
    [Requirement("REQ-QUIC-RFC9464-0031")]
    [Requirement("REQ-QUIC-RFC9464-0033")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestRejectsEmptyHashAlgorithmList()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }
}
