// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsProvisioningResponderTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0051")]
    [Requirement("REQ-QUIC-RFC9464-0053")]
    [Requirement("REQ-QUIC-RFC9464-0054")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SupportAdvertisementIncludesZeroLengthIpAttributes()
    {
        IReadOnlyList<EncryptedDnsProvisioningAttribute> attributes =
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest();

        Assert.Collection(
            attributes,
            attribute =>
            {
                Assert.Equal(EncryptedDnsProvisioningAddressFamily.Ip4, attribute.AddressFamily);
                Assert.Equal(0, attribute.Length);
            },
            attribute =>
            {
                Assert.Equal(EncryptedDnsProvisioningAddressFamily.Ip6, attribute.AddressFamily);
                Assert.Equal(0, attribute.Length);
            });
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0051")]
    [Requirement("REQ-QUIC-RFC9464-0053")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SupportAdvertisementRejectsMissingAddressFamilies()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest(includeIpv4: false, includeIpv6: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0055")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestMayContainSpecificSuggestedResolverList()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, attribute.PayloadType);
        Assert.Equal(1, attribute.AddressCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0054")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SpecificResolverRequestUsesNonZeroLength()
    {
        EncryptedDnsProvisioningAttribute attribute = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.True(attribute.Length > 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestRejectsEmptySpecificResolverListForReplyShape()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.CreateEmpty(
                EncryptedDnsProvisioningPayloadType.Reply,
                EncryptedDnsProvisioningAddressFamily.Ip4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0056")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestMayIncludeDigestInfoHashAlgorithmList()
    {
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([1, 2]);

        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, digestInfo.PayloadType);
        Assert.Equal([1, 2], digestInfo.HashAlgorithmIdentifiers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0056")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestInfoRequestRejectsMissingHashAlgorithmList()
    {
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("RFC9464-S4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplyIgnoresDuplicateIdenticalRequestAttributesAfterFirst()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request, request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)]));

        Assert.False(response.RequestDiscarded);
        Assert.Single(response.Attributes);
    }

    [Fact]
    [Requirement("RFC9464-S4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyRejectsNonRequestAttributes()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponder.CreateReply(
                [CreateIpv4Reply(priority: 1)],
                EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0058")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplyMayDiscardRequestWithTooManyRepeatedAttributes()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);

        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request, request, request],
            EncryptedDnsProvisioningResponseOptions.Create(
                [CreateIpv4Reply(priority: 1)],
                duplicateAttributeDiscardThreshold: 1));

        Assert.True(response.RequestDiscarded);
        Assert.Empty(response.Attributes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0058")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseOptionsRejectInvalidDuplicateDiscardThreshold()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            EncryptedDnsProvisioningResponseOptions.Create(
                [CreateIpv4Reply(priority: 1)],
                duplicateAttributeDiscardThreshold: 0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0052")]
    [Requirement("RFC9464-S4-P5-S1-R01")]
    [Requirement("REQ-QUIC-RFC9464-0060")]
    [Requirement("RFC9464-S4-P5-S3-R01")]
    [Requirement("REQ-QUIC-RFC9464-0062")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplyReturnsSupportedAddressFamilyConfigurationWithAlpn()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)]));

        EncryptedDnsProvisioningAttribute attribute = Assert.Single(response.Attributes);
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Reply, attribute.PayloadType);
        Assert.Equal(1, attribute.AddressCount);
        Assert.Contains("alpn", attribute.ServiceParameterKeys);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0052")]
    [Requirement("RFC9464-S4-P5-S1-R01")]
    [Requirement("REQ-QUIC-RFC9464-0060")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseOptionsRejectReplyConfigurationsWithoutAddresses()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponseOptions.Create(
                [EncryptedDnsProvisioningAttribute.CreateEmpty(
                    EncryptedDnsProvisioningPayloadType.Request,
                    EncryptedDnsProvisioningAddressFamily.Ip4)]));
    }

    [Fact]
    [Requirement("RFC9464-S4-P5-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ResponseOptionsRejectReplyConfigurationsWithoutAlpnByDefault()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4ReplyWithoutAlpn(priority: 1)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0062")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyCanIgnoreSuggestedValuesFromRequest()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "suggested.example",
            [IPAddress.Parse("192.0.2.100")]);
        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)]));

        EncryptedDnsProvisioningAttribute attribute = Assert.Single(response.Attributes);
        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
        Assert.Equal([IPAddress.Parse("192.0.2.53")], attribute.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0063")]
    [Requirement("REQ-QUIC-RFC9464-0064")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplyReturnsMultipleInstancesOrderedByServicePriority()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create(
                [CreateIpv4Reply(priority: 20, "secondary.example"), CreateIpv4Reply(priority: 10, "primary.example")]));

        Assert.Collection(
            response.Attributes,
            attribute => Assert.Equal(10, attribute.ServicePriority),
            attribute => Assert.Equal(20, attribute.ServicePriority));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0063")]
    [Requirement("REQ-QUIC-RFC9464-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyDoesNotReturnUnsupportedAddressFamilies()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip6);
        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)]));

        Assert.Empty(response.Attributes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ReplyOptionallyReturnsDigestInfo()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA]);

        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)], digestInfo));

        Assert.Same(digestInfo, response.DigestInfo);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0065")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyOmitsDigestInfoWhenDisabled()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo =
            EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
                EncryptedDnsProvisioningPayloadType.Reply,
                authenticationDomainName: null,
                EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                [0xAA]);

        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(priority: 1)], digestInfo, includeDigestInfo: false));

        Assert.Null(response.DigestInfo);
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4Reply(ushort priority, string authenticationDomainName = "resolver.example")
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            authenticationDomainName,
            [IPAddress.Parse("192.0.2.53")],
            ["alpn"],
            priority);
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4ReplyWithoutAlpn(ushort priority)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")],
            [],
            priority);
    }
}
