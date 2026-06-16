// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Security.Cryptography;
using System.Text;

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
        Assert.Equal(4 + "resolver.example.".Length + (2 * 4) + 4, attribute.Length);
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

        Assert.Equal(4 + "resolver.example.".Length + 16 + 4, attribute.Length);
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
    [Requirement("REQ-QUIC-RFC9464-0001")]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [Requirement("REQ-QUIC-RFC9464-0010")]
    [Requirement("REQ-QUIC-RFC9464-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpAttributeEncodeWritesHeaderAndFieldsInRfc9464Order()
    {
        EncryptedDnsProvisioningAttribute attribute =
            EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example.",
                [IPAddress.Parse("192.0.2.53")],
                [EncryptedDnsProvisioningServiceParameter.Create(
                    EncryptedDnsProvisioningServiceParameter.AlpnKey,
                    [0x02, (byte)'h', (byte)'3'])],
                servicePriority: 1);

        byte[] encoded = attribute.Encode();

        byte[] expected =
        [
            0x00, 0x1B,
            0x00, 0x20,
            0x00, 0x01,
            0x01,
            0x11,
            0xC0, 0x00, 0x02, 0x35,
            .. Encoding.ASCII.GetBytes("resolver.example."),
            0x00, 0x01,
            0x00, 0x03,
            0x02, (byte)'h', (byte)'3',
        ];
        Assert.Equal(expected, encoded);
        Assert.Equal(attribute.Length, BitConverter.ToUInt16(encoded[2..4].Reverse().ToArray()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0002")]
    [Requirement("REQ-QUIC-RFC9464-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpAttributeDecodeIgnoresReservedBitAndPreservesWireParameters()
    {
        EncryptedDnsProvisioningAttribute attribute =
            EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example.",
                [IPAddress.Parse("192.0.2.53")],
                [EncryptedDnsProvisioningServiceParameter.Create(3, [0x01, 0xBB])],
                servicePriority: 5);
        byte[] encoded = attribute.Encode();
        encoded[0] |= 0x80;

        EncryptedDnsProvisioningAttribute decoded =
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded);

        Assert.Equal(5, decoded.ServicePriority);
        Assert.Equal([IPAddress.Parse("192.0.2.53")], decoded.Addresses);
        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
        EncryptedDnsProvisioningServiceParameter parameter = Assert.Single(decoded.ServiceParameters);
        Assert.Equal(3, parameter.Key);
        Assert.Equal([0x01, 0xBB], parameter.Value.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsAliasModeZeroOnEncodeAndDecode()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "resolver.example",
                [IPAddress.Parse("192.0.2.53")],
                servicePriority: 0));

        byte[] encoded = [0x00, 0x1B, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00];
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeDecodeRejectsZeroAddressCountForReplyAndSet()
    {
        byte[] encoded = [0x00, 0x1B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Set, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0001")]
    [Requirement("REQ-QUIC-RFC9464-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeDecodeRejectsMalformedFieldLengths()
    {
        byte[] lengthMismatch = [0x00, 0x1B, 0x00, 0x05, 0x00, 0x01, 0x01, 0x00];
        byte[] truncatedServiceParameter = [0x00, 0x1B, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, lengthMismatch));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, truncatedServiceParameter));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0011")]
    [Requirement("REQ-QUIC-RFC9464-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpAttributeAcceptsNonZeroPriorityAndReplyAddressCount()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            servicePriority: 1);

        Assert.Equal(1, attribute.ServicePriority);
        Assert.Equal(1, attribute.AddressCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0018")]
    [Requirement("REQ-QUIC-RFC9464-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpAttributeRejectsForbiddenHintServiceParametersByNumericKey()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(
                EncryptedDnsProvisioningServiceParameter.Ipv4HintKey,
                [192, 0, 2, 53]));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningServiceParameter.Create(
                EncryptedDnsProvisioningServiceParameter.Ipv6HintKey,
                [0x20, 0x01, 0x0D, 0xB8]));
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0022")]
    [Requirement("REQ-QUIC-RFC9464-0037")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoRequestEncodeWritesFieldsInRfc9464Order()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);

        byte[] encoded = attribute.Encode();

        Assert.Equal([0x00, 0x1D, 0x00, 0x06, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02], encoded);
        EncryptedDnsProvisioningDigestInfoAttribute decoded =
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, encoded);
        Assert.Equal([1, 2], decoded.HashAlgorithmIdentifiers);
        Assert.Empty(decoded.AuthenticationDomainName);
        Assert.True(decoded.CertificateDigest.IsEmpty);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0021")]
    [Requirement("REQ-QUIC-RFC9464-0034")]
    [Requirement("REQ-QUIC-RFC9464-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoReplyEncodeWritesDigestFieldsInRfc9464Order()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA, 0xBB, 0xCC]);

        byte[] encoded = attribute.Encode();

        Assert.Equal([0x00, 0x1D, 0x00, 0x07, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC], encoded);
        EncryptedDnsProvisioningDigestInfoAttribute decoded =
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded);
        Assert.Equal(1, decoded.HashAlgorithmCount);
        Assert.Equal([EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier], decoded.HashAlgorithmIdentifiers);
        Assert.Equal([0xAA, 0xBB, 0xCC], decoded.CertificateDigest.ToArray());
        Assert.True(decoded.AppliesToProvisioningAttributeAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0021")]
    [Requirement("REQ-QUIC-RFC9464-0034")]
    [Requirement("REQ-QUIC-RFC9464-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoReplyDecodeRejectsMalformedLayoutAndLength()
    {
        byte[] wrongLength = [0x00, 0x1D, 0x00, 0x07, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB];
        byte[] tooShortForHashIdentifier = [0x00, 0x1D, 0x00, 0x03, 0x01, 0x00, 0x00];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, wrongLength));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, tooShortForHashIdentifier));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0022")]
    [Requirement("REQ-QUIC-RFC9464-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestDecodeRejectsMalformedHeaderFields()
    {
        byte[] wrongAttributeType = [0x00, 0x1C, 0x00, 0x04, 0x01, 0x00, 0x00, 0x02];
        byte[] nameLengthInRequest = [0x00, 0x1D, 0x00, 0x04, 0x01, 0x01, 0x00, 0x02];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, wrongAttributeType));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, nameLengthInRequest));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoAcceptsRegisteredAndPrivateUseHashAlgorithmIdentifiers()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 7, 1024]);

        Assert.Equal([1, 7, 1024], attribute.HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRejectsUnregisteredHashAlgorithmIdentifier()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([0]));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            hashAlgorithmIdentifier: 8,
            [0xAA]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0039")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoReplyUsesOneSelectedHashAlgorithm()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA]);

        Assert.Equal(1, attribute.HashAlgorithmCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0039")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoReplyRejectsHashAlgorithmCountOtherThanOne()
    {
        byte[] encoded = [0x00, 0x1D, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0040")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoReplyAdnLengthMatchesAuthenticationDomainNameBytes()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.Equal(Encoding.ASCII.GetByteCount("resolver.example."), attribute.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0040")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoReplyRejectsAdnLengthBeyondAvailableData()
    {
        byte[] encoded = [0x00, 0x1D, 0x00, 0x05, 0x01, 0x04, (byte)'d', 0x00, 0x02];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0041")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoZeroAdnLengthAppliesToProvisioningAttributeAdn()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA]);

        Assert.True(attribute.AppliesToProvisioningAttributeAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0041")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoNonZeroAdnLengthDoesNotApplyToProvisioningAttributeAdn()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.False(attribute.AppliesToProvisioningAttributeAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0042")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoAcceptsFullyQualifiedAuthenticationDomainName()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "Resolver.Example.",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0042")]
    [Requirement("REQ-QUIC-RFC9464-0043")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRejectsInvalidAuthenticationDomainNames()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "192.0.2.53",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example\r",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0043")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoAuthenticationDomainNameOmitsTerminators()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.DoesNotContain('\0', attribute.AuthenticationDomainName);
        Assert.DoesNotContain('\r', attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0044")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoAuthenticationDomainNameRequiresMultipleProvisionedNames()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: false));

        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0044")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoIncludesAuthenticationDomainNameWhenMultipleNamesArePresent()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                "resolver.example",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA],
                multipleAuthenticationDomainNames: true);

        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0045")]
    [Requirement("REQ-QUIC-RFC9464-0046")]
    [Requirement("REQ-QUIC-RFC9464-0047")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoReplyPreservesSelectedHashIdentifierAndDigest()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Set,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA, 0xBB, 0xCC]);

        Assert.Equal([EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier], attribute.HashAlgorithmIdentifiers);
        Assert.Equal([0xAA, 0xBB, 0xCC], attribute.CertificateDigest.ToArray());
        Assert.Equal(attribute.Length - 4 - attribute.AuthenticationDomainNameLength, attribute.CertificateDigest.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0045")]
    [Requirement("REQ-QUIC-RFC9464-0046")]
    [Requirement("REQ-QUIC-RFC9464-0047")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoReplyRejectsInvalidHashDigestAndDigestLength()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                hashAlgorithmIdentifier: 0,
                [0xAA]));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                []));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(
                EncryptedDnsProvisioningPayloadType.Reply,
                [0x00, 0x1D, 0x00, 0x04, 0x01, 0x00, 0x00, 0x02]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0048")]
    [Requirement("REQ-QUIC-RFC9464-0049")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoAckEncodesZeroLengthData()
    {
        EncryptedDnsProvisioningDigestInfoAttribute attribute = EncryptedDnsProvisioningDigestInfoAttribute.CreateAck();

        Assert.Equal([0x00, 0x1D, 0x00, 0x00], attribute.Encode());
        Assert.True(attribute.OmitsTrailingFields);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(
                EncryptedDnsProvisioningPayloadType.Reply,
                attribute.Encode()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0048")]
    [Requirement("REQ-QUIC-RFC9464-0049")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoZeroLengthDataIsLimitedToAck()
    {
        byte[] encoded = EncryptedDnsProvisioningDigestInfoAttribute.CreateAck().Encode();

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, encoded));
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0074")]
    [Requirement("REQ-QUIC-RFC9464-0075")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestInfoComputesSha2256SubjectPublicKeyInfoDigest()
    {
        byte[] subjectPublicKeyInfoDer = [0x30, 0x03, 0x01, 0x02, 0x03];

        byte[] digest = EncryptedDnsProvisioningDigestInfoAttribute
            .ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfoDer);

        Assert.Equal(SHA256.HashData(subjectPublicKeyInfoDer), digest);
        Assert.Equal(EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier, 2);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0074")]
    [Requirement("REQ-QUIC-RFC9464-0075")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRejectsEmptySpkiDigestInputAndUnknownHashIdentifier()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest([]));
        Assert.False(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(0));
    }
}
