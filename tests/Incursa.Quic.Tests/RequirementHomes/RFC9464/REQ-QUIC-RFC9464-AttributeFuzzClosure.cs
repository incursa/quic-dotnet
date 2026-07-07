// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9464_AttributeFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0002")]
    [Requirement("REQ-QUIC-RFC9464-0003")]
    [Requirement("REQ-QUIC-RFC9464-0023")]
    [Requirement("REQ-QUIC-RFC9464-0024")]
    [Requirement("REQ-QUIC-RFC9464-0035")]
    [Requirement("REQ-QUIC-RFC9464-0036")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReservedBitsAreIgnoredOnReceiptAndClearedOnSend()
    {
        EncryptedDnsProvisioningAttribute ipAttribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]);
        byte[] ipEncoded = ipAttribute.Encode();
        ipEncoded[0] |= 0x80;

        EncryptedDnsProvisioningDigestInfoAttribute digestAttribute =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);
        byte[] digestEncoded = digestAttribute.Encode();
        digestEncoded[0] |= 0x80;

        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: true));
        Assert.True(EncryptedDnsProvisioningAttribute.ShouldIgnoreReservedBit(reservedBitSet: false));
        Assert.False(ipAttribute.ReservedBitSet);
        Assert.False(digestAttribute.ReservedBitSet);
        Assert.Equal("resolver.example.", EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, ipEncoded).AuthenticationDomainName);
        Assert.Equal([1, 2], EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, digestEncoded).HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0001")]
    [Requirement("REQ-QUIC-RFC9464-0004")]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [Requirement("REQ-QUIC-RFC9464-0008")]
    [Requirement("REQ-QUIC-RFC9464-0009")]
    [Requirement("REQ-QUIC-RFC9464-0013")]
    [Requirement("REQ-QUIC-RFC9464-0014")]
    [Requirement("REQ-QUIC-RFC9464-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpAttributesEncodeLengthAddressAndAdnFieldsInOrder()
    {
        foreach ((EncryptedDnsProvisioningAddressFamily family, IPAddress[] addresses, int addressOctets) in new[]
        {
            (EncryptedDnsProvisioningAddressFamily.Ip4, new[] { IPAddress.Parse("192.0.2.53"), IPAddress.Parse("198.51.100.53") }, 4),
            (EncryptedDnsProvisioningAddressFamily.Ip6, new[] { IPAddress.Parse("2001:db8::53") }, 16),
        })
        {
            EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
                EncryptedDnsProvisioningPayloadType.Reply,
                family,
                "Resolver.Example.",
                addresses,
                ["alpn", "port"],
                servicePriority: 1);
            byte[] encoded = attribute.Encode();
            int expectedLength = 4 + "resolver.example.".Length + (addresses.Length * addressOctets) + 8;

            Assert.Equal(2, EncryptedDnsProvisioningAttribute.LengthFieldOctets);
            Assert.Equal(1, EncryptedDnsProvisioningAttribute.AuthenticationDomainNameLengthFieldOctets);
            Assert.Equal(expectedLength, attribute.Length);
            Assert.Equal(encoded.Length - 4, attribute.Length);
            Assert.Equal(addresses.Length, attribute.AddressCount);
            Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
            Assert.Equal(addresses, attribute.Addresses);
            Assert.Equal(1, ReadUInt16(encoded, 4));
            Assert.Equal(addresses.Length, encoded[6]);
            Assert.Equal("resolver.example.".Length, encoded[7]);
        }

        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip6,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0006")]
    [Requirement("REQ-QUIC-RFC9464-0007")]
    [Requirement("REQ-QUIC-RFC9464-0011")]
    [Requirement("REQ-QUIC-RFC9464-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpAttributesValidateZeroLengthAliasModeAndAddressCountRules()
    {
        foreach (EncryptedDnsProvisioningPayloadType payloadType in new[] { EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningPayloadType.Ack })
        {
            EncryptedDnsProvisioningAttribute empty = EncryptedDnsProvisioningAttribute.CreateEmpty(
                payloadType,
                EncryptedDnsProvisioningAddressFamily.Ip4);

            Assert.Equal(0, empty.Length);
            Assert.Equal(0, empty.AddressCount);
            Assert.Empty(empty.AuthenticationDomainName);
            Assert.Empty(empty.Addresses);
            Assert.True(empty.OmitsTrailingFields);
            Assert.Equal([0x00, 0x1B, 0x00, 0x00], empty.Encode());
        }

        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            servicePriority: 0));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.Decode(
            EncryptedDnsProvisioningPayloadType.Reply,
            [0x00, 0x1B, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0010")]
    [Requirement("REQ-QUIC-RFC9464-0016")]
    [Requirement("REQ-QUIC-RFC9464-0017")]
    [Requirement("REQ-QUIC-RFC9464-0018")]
    [Requirement("REQ-QUIC-RFC9464-0019")]
    [Requirement("REQ-QUIC-RFC9464-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpAttributesValidateSvcbPriorityAdnAndSvcParams()
    {
        EncryptedDnsProvisioningAttribute attribute =
            EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4,
                "Resolver.Example.",
                [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("198.51.100.53")],
                [
                    EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'h', (byte)'3']),
                    EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.PortKey, [0x01, 0xBB]),
                ],
                servicePriority: 5);

        byte[] encoded = attribute.Encode();
        EncryptedDnsProvisioningAttribute decoded = EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded);

        Assert.Equal(5, decoded.ServicePriority);
        Assert.Equal("resolver.example.", decoded.AuthenticationDomainName);
        Assert.DoesNotContain('\0', decoded.AuthenticationDomainName);
        Assert.DoesNotContain('\r', decoded.AuthenticationDomainName);
        Assert.Equal(["alpn", "port"], decoded.ServiceParameterKeys);
        Assert.Equal(2, decoded.Addresses.Count);
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example\0",
            [IPAddress.Parse("192.0.2.53")]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "192.0.2.53",
            [IPAddress.Parse("192.0.2.53")]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningServiceParameter.Create(
            EncryptedDnsProvisioningServiceParameter.Ipv4HintKey,
            [192, 0, 2, 53]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            [""]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0022")]
    [Requirement("REQ-QUIC-RFC9464-0025")]
    [Requirement("REQ-QUIC-RFC9464-0026")]
    [Requirement("REQ-QUIC-RFC9464-0027")]
    [Requirement("REQ-QUIC-RFC9464-0028")]
    [Requirement("REQ-QUIC-RFC9464-0029")]
    [Requirement("REQ-QUIC-RFC9464-0030")]
    [Requirement("REQ-QUIC-RFC9464-0031")]
    [Requirement("REQ-QUIC-RFC9464-0032")]
    [Requirement("REQ-QUIC-RFC9464-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DigestInfoRequestEncodesHashAlgorithmListWithoutPadding()
    {
        EncryptedDnsProvisioningDigestInfoAttribute request =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2, 7, 1024]);
        byte[] encoded = request.Encode();
        EncryptedDnsProvisioningDigestInfoAttribute decoded =
            EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, encoded);

        Assert.Equal(29, EncryptedDnsProvisioningDigestInfoAttribute.AttributeType);
        Assert.Equal(2 + (2 * 4), request.Length);
        Assert.Equal(encoded.Length - 4, request.Length);
        Assert.Equal(4, request.HashAlgorithmCount);
        Assert.Equal(0, request.AuthenticationDomainNameLength);
        Assert.Equal([1, 2, 7, 1024], decoded.HashAlgorithmIdentifiers);
        Assert.True(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(1024));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([0]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.Decode(
            EncryptedDnsProvisioningPayloadType.Request,
            [0x00, 0x1C, 0x00, 0x04, 0x01, 0x00, 0x00, 0x02]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.Decode(
            EncryptedDnsProvisioningPayloadType.Request,
            [0x00, 0x1D, 0x00, 0x04, 0x01, 0x01, 0x00, 0x02]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0021")]
    [Requirement("REQ-QUIC-RFC9464-0034")]
    [Requirement("REQ-QUIC-RFC9464-0037")]
    [Requirement("REQ-QUIC-RFC9464-0038")]
    [Requirement("REQ-QUIC-RFC9464-0039")]
    [Requirement("REQ-QUIC-RFC9464-0040")]
    [Requirement("REQ-QUIC-RFC9464-0041")]
    [Requirement("REQ-QUIC-RFC9464-0042")]
    [Requirement("REQ-QUIC-RFC9464-0043")]
    [Requirement("REQ-QUIC-RFC9464-0044")]
    [Requirement("REQ-QUIC-RFC9464-0045")]
    [Requirement("REQ-QUIC-RFC9464-0046")]
    [Requirement("REQ-QUIC-RFC9464-0047")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DigestInfoReplyAndSetEncodeSelectedHashDigestAndOptionalAdn()
    {
        EncryptedDnsProvisioningDigestInfoAttribute sharedAdn =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA, 0xBB, 0xCC]);
        EncryptedDnsProvisioningDigestInfoAttribute namedAdn =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Set,
                "Resolver.Example.",
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0x01, 0x02],
                multipleAuthenticationDomainNames: true);

        foreach (EncryptedDnsProvisioningDigestInfoAttribute attribute in new[] { sharedAdn, namedAdn })
        {
            byte[] encoded = attribute.Encode();
            EncryptedDnsProvisioningDigestInfoAttribute decoded =
                EncryptedDnsProvisioningDigestInfoAttribute.Decode(attribute.PayloadType, encoded);

            Assert.Equal(1, decoded.HashAlgorithmCount);
            Assert.Equal([EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier], decoded.HashAlgorithmIdentifiers);
            Assert.Equal(attribute.CertificateDigest.ToArray(), decoded.CertificateDigest.ToArray());
            Assert.Equal(attribute.Length - 4 - attribute.AuthenticationDomainNameLength, attribute.CertificateDigest.Length);
            Assert.DoesNotContain('\0', decoded.AuthenticationDomainName);
            Assert.DoesNotContain('\r', decoded.AuthenticationDomainName);
        }

        Assert.True(sharedAdn.AppliesToProvisioningAttributeAuthenticationDomainName);
        Assert.False(namedAdn.AppliesToProvisioningAttributeAuthenticationDomainName);
        Assert.Equal("resolver.example.", namedAdn.AuthenticationDomainName);
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            "resolver.example",
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            [0xAA],
            multipleAuthenticationDomainNames: false));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            "resolver.example\r",
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            [0xAA],
            multipleAuthenticationDomainNames: true));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            hashAlgorithmIdentifier: 0,
            [0xAA]));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            []));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.Decode(
            EncryptedDnsProvisioningPayloadType.Reply,
            [0x00, 0x1D, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0048")]
    [Requirement("REQ-QUIC-RFC9464-0049")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DigestInfoAckMayCarryOnlyZeroLengthData()
    {
        EncryptedDnsProvisioningDigestInfoAttribute ack = EncryptedDnsProvisioningDigestInfoAttribute.CreateAck();
        byte[] encoded = ack.Encode();

        Assert.Equal([0x00, 0x1D, 0x00, 0x00], encoded);
        Assert.True(ack.OmitsTrailingFields);
        Assert.Equal(0, ack.Length);
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Request, encoded));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0074")]
    [Requirement("RFC9464-S5-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Sha2256SubjectPublicKeyInfoDigestUsesMandatoryHash()
    {
        foreach (byte[] subjectPublicKeyInfoDer in new[]
        {
            new byte[] { 0x30, 0x03, 0x01, 0x02, 0x03 },
            Encoding.ASCII.GetBytes("subject-public-key-info"),
        })
        {
            Assert.Equal(
                SHA256.HashData(subjectPublicKeyInfoDer),
                EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfoDer));
        }

        Assert.Equal(2, EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier);
        Assert.True(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier));
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest([]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0001_IpAttributeFieldOrder()
    {
        byte[] encoded = CreateIp4Attribute().Encode();

        Assert.Equal(EncryptedDnsProvisioningAttribute.Ip4AttributeType, ReadUInt16(encoded, 0));
        Assert.Equal(ReadUInt16(encoded, 2), encoded.Length - 4);
        Assert.Equal(1, ReadUInt16(encoded, 4));
        Assert.Equal(1, encoded[6]);
        Assert.Equal("resolver.example.".Length, encoded[7]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0004_IpAttributeLengthFieldIsTwoOctets()
    {
        Assert.Equal(2, EncryptedDnsProvisioningAttribute.LengthFieldOctets);
        Assert.Equal(typeof(ushort), typeof(EncryptedDnsProvisioningAttribute).GetProperty(nameof(EncryptedDnsProvisioningAttribute.Length))?.PropertyType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0005_IpAttributeLengthIsEnclosedDataLength()
    {
        EncryptedDnsProvisioningAttribute attribute = CreateIp4Attribute();

        Assert.Equal(attribute.Encode().Length - 4, attribute.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0008_Ip4AttributeLengthFormula()
    {
        EncryptedDnsProvisioningAttribute attribute = CreateIp4Attribute();

        Assert.Equal(4 + "resolver.example.".Length + 4 + 4, attribute.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0009_Ip6AttributeLengthFormula()
    {
        EncryptedDnsProvisioningAttribute attribute = CreateIp6Attribute();

        Assert.Equal(4 + "resolver.example.".Length + 16 + 4, attribute.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0013_IpAttributeAdnLengthIsOneOctet()
    {
        EncryptedDnsProvisioningAttribute attribute = CreateIp4Attribute();

        Assert.Equal(1, EncryptedDnsProvisioningAttribute.AuthenticationDomainNameLengthFieldOctets);
        Assert.Equal("resolver.example.".Length, attribute.Encode()[7]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0014_Ip4AttributeContainsFourOctetAddresses()
    {
        byte[] encoded = CreateIp4Attribute().Encode();

        Assert.Equal([192, 0, 2, 53], encoded[8..12]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0015_Ip6AttributeContainsSixteenOctetAddresses()
    {
        byte[] encoded = CreateIp6Attribute().Encode();

        Assert.Equal(IPAddress.Parse("2001:db8::53").GetAddressBytes(), encoded[8..24]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0021_DigestInfoReplyContainsFieldsInOrder()
    {
        byte[] encoded = CreateDigestReply().Encode();

        Assert.Equal(EncryptedDnsProvisioningDigestInfoAttribute.AttributeType, ReadUInt16(encoded, 0));
        Assert.Equal(encoded.Length - 4, ReadUInt16(encoded, 2));
        Assert.Equal(1, encoded[4]);
        Assert.Equal(0, encoded[5]);
        Assert.Equal(EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier, ReadUInt16(encoded, 6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0022_DigestInfoRequestContainsHashListFieldsInOrder()
    {
        Assert.Equal([0x00, 0x1D, 0x00, 0x06, 0x02, 0x00, 0x00, 0x01, 0x00, 0x02], CreateDigestRequest().Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0025_DigestInfoRequestAttributeTypeIsTwentyNine()
    {
        Assert.Equal(29, EncryptedDnsProvisioningDigestInfoAttribute.AttributeType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0026_DigestInfoLengthIsTwoOctetUnsignedValue()
    {
        Assert.Equal(typeof(ushort), typeof(EncryptedDnsProvisioningDigestInfoAttribute).GetProperty(nameof(EncryptedDnsProvisioningDigestInfoAttribute.Length))?.PropertyType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0027_DigestInfoRequestLengthFormula()
    {
        Assert.Equal(2 + (2 * 2), CreateDigestRequest().Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0028_DigestInfoHashAlgorithmCountMatchesList()
    {
        Assert.Equal(2, CreateDigestRequest().HashAlgorithmCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0029_DigestInfoHashAlgorithmCountDerivesFromLength()
    {
        EncryptedDnsProvisioningDigestInfoAttribute request = CreateDigestRequest();

        Assert.Equal((request.Length - 2) / 2, request.HashAlgorithmCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0030_DigestInfoRequestAdnLengthIsZero()
    {
        Assert.Equal(0, CreateDigestRequest().AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0031_DigestInfoRequestContainsSupportedHashIdentifiers()
    {
        Assert.Equal([1, 2], CreateDigestRequest().HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0032_DigestInfoHashIdentifiersComeFromRegistry()
    {
        Assert.True(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(1));
        Assert.True(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(1024));
        Assert.False(EncryptedDnsProvisioningDigestInfoAttribute.IsRegisteredHashAlgorithmIdentifier(0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0033_DigestInfoHashIdentifiersHaveNoPadding()
    {
        Assert.Equal(8, EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2, 4]).Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0034_DigestInfoReplyUsesTableLayout()
    {
        Assert.Equal([0x00, 0x1D, 0x00, 0x07, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0xCC], CreateDigestReply().Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0037")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0037_DigestInfoReplyAttributeTypeIsTwentyNine()
    {
        Assert.Equal(29, ReadUInt16(CreateDigestReply().Encode(), 0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0038_DigestInfoReplyLengthIsDataLength()
    {
        EncryptedDnsProvisioningDigestInfoAttribute reply = CreateDigestReply();

        Assert.Equal(reply.Encode().Length - 4, reply.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0039")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0039_DigestInfoReplyUsesOneHashAlgorithm()
    {
        Assert.Equal(1, CreateDigestReply().HashAlgorithmCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0040")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0040_DigestInfoReplyAdnLengthMatchesNameBytes()
    {
        EncryptedDnsProvisioningDigestInfoAttribute reply = CreateNamedDigestReply();

        Assert.Equal(Encoding.ASCII.GetByteCount("resolver.example."), reply.AuthenticationDomainNameLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0041")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0041_ZeroAdnLengthAppliesToProvisioningAttributeAdn()
    {
        Assert.True(CreateDigestReply().AppliesToProvisioningAttributeAuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0042")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0042_DigestInfoAdnIsFullyQualifiedDomainName()
    {
        Assert.Equal("resolver.example.", CreateNamedDigestReply().AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0043")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0043_DigestInfoAdnDoesNotContainTerminators()
    {
        string name = CreateNamedDigestReply().AuthenticationDomainName;

        Assert.DoesNotContain('\0', name);
        Assert.DoesNotContain('\r', name);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0044")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0044_DigestInfoAdnRequiresMultipleNames()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            "resolver.example",
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            [0xAA],
            multipleAuthenticationDomainNames: false));
        Assert.Equal("resolver.example.", CreateNamedDigestReply().AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0045_DigestInfoReplyPreservesSelectedHashIdentifier()
    {
        Assert.Equal([EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier], CreateDigestReply().HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0046")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0046_DigestInfoReplyCarriesCertificateDigest()
    {
        Assert.Equal([0xAA, 0xBB, 0xCC], CreateDigestReply().CertificateDigest.ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0047")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0047_DigestInfoReplyDigestLengthFormula()
    {
        EncryptedDnsProvisioningDigestInfoAttribute reply = CreateDigestReply();

        Assert.Equal(reply.Length - 4 - reply.AuthenticationDomainNameLength, reply.CertificateDigest.Length);
    }

    private static EncryptedDnsProvisioningAttribute CreateIp4Attribute()
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            ["alpn"],
            servicePriority: 1);
    }

    private static EncryptedDnsProvisioningAttribute CreateIp6Attribute()
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Set,
            EncryptedDnsProvisioningAddressFamily.Ip6,
            "resolver.example",
            [IPAddress.Parse("2001:db8::53")],
            ["port"],
            servicePriority: 1);
    }

    private static EncryptedDnsProvisioningDigestInfoAttribute CreateDigestRequest()
    {
        return EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);
    }

    private static EncryptedDnsProvisioningDigestInfoAttribute CreateDigestReply()
    {
        return EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            [0xAA, 0xBB, 0xCC]);
    }

    private static EncryptedDnsProvisioningDigestInfoAttribute CreateNamedDigestReply()
    {
        return EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            "resolver.example",
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            [0xAA],
            multipleAuthenticationDomainNames: true);
    }

    private static ushort ReadUInt16(byte[] source, int offset)
    {
        return (ushort)((source[offset] << 8) | source[offset + 1]);
    }
}
