// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9464_PolicyExchangeFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0050")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0050_BadlyFormattedAttributesAreRejectedBeforePolicyUse()
    {
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, [0x00, 0x1B, 0x00, 0x05, 0x00]));

        EncryptedDnsProvisioningAttribute reply = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));
        EncryptedDnsProvisioningAttribute decoded =
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, reply.Encode());
        Assert.Equal(reply.AuthenticationDomainName, decoded.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0051")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0051_InitiatorAdvertisesEncryptedDnsSupportInCfgRequest()
    {
        IReadOnlyList<EncryptedDnsProvisioningAttribute> request =
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest();

        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, request[0].PayloadType);
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, request[1].PayloadType);
        Assert.Equal([EncryptedDnsProvisioningAddressFamily.Ip4, EncryptedDnsProvisioningAddressFamily.Ip6], request.Select(static item => item.AddressFamily).ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0052_ResponderSuppliesEncryptedDnsConfigurationInCfgReply()
    {
        EncryptedDnsProvisioningResponse response = CreateReply(
            [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)],
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))]);

        EncryptedDnsProvisioningAttribute attribute = Assert.Single(response.Attributes);
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Reply, attribute.PayloadType);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(attribute.Addresses));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0053")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0053_SupportRequestIncludesEitherOrBothAddressFamilies()
    {
        Assert.Equal(EncryptedDnsProvisioningAddressFamily.Ip4, Assert.Single(
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest(includeIpv4: true, includeIpv6: false)).AddressFamily);
        Assert.Equal(EncryptedDnsProvisioningAddressFamily.Ip6, Assert.Single(
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest(includeIpv4: false, includeIpv6: true)).AddressFamily);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponder.CreateSupportAdvertisementRequest(includeIpv4: false, includeIpv6: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0054")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0054_UnspecifiedResolverRequestsUseZeroLengthAttributes()
    {
        EncryptedDnsProvisioningAttribute empty = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningAttribute suggested = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53")]);

        Assert.Equal(0, empty.Length);
        Assert.True(suggested.Length > 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0055")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0055_RequestMayCarryEmptyOrDistinctSuggestedResolvers()
    {
        EncryptedDnsProvisioningAttribute empty = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningAttribute suggested = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [IPAddress.Parse("192.0.2.53"), IPAddress.Parse("192.0.2.54")]);

        Assert.Equal(0, empty.AddressCount);
        Assert.Equal(2, suggested.AddressCount);
        Assert.Equal(2, suggested.Addresses.Distinct().Count());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0056")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0056_RequestMayIncludeDigestInfoHashAlgorithms()
    {
        EncryptedDnsProvisioningConfigurationPayload request =
            EncryptedDnsProvisioningExchangePlanner.CreateSupportRequest(
                digestHashAlgorithmIdentifiers:
                [
                    EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
                    1024,
                ]);

        Assert.NotNull(request.DigestInfo);
        Assert.Equal([EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier, 1024], request.DigestInfo.HashAlgorithmIdentifiers.ToArray());
        Assert.Throws<ArgumentException>(() => EncryptedDnsProvisioningDigestInfoAttribute.CreateRequest([]));
    }

    [Fact]
    [Requirement("RFC9464-S4-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S4P4S1_DuplicateIdenticalRequestsProcessFirstOccurrenceOnly()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);

        EncryptedDnsProvisioningResponse response = CreateReply(
            [request, request],
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))]);

        Assert.False(response.RequestDiscarded);
        Assert.Single(response.Attributes);
    }

    [Fact]
    [Requirement("RFC9464-S4-P3-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S4P3P2_RepeatedAttributeThresholdMayDiscardFullRequest()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);

        EncryptedDnsProvisioningResponse response = EncryptedDnsProvisioningResponder.CreateReply(
            [request, request, request],
            EncryptedDnsProvisioningResponseOptions.Create(
                [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
                duplicateAttributeDiscardThreshold: 1));

        Assert.True(response.RequestDiscarded);
        Assert.Empty(response.Attributes);
    }

    [Fact]
    [Requirement("RFC9464-S4-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S4P5S1_ResponderReturnsSupportedFamilyAttributesWithConfiguration()
    {
        EncryptedDnsProvisioningResponse response = CreateReply(
            [
                EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4),
                EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip6),
            ],
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))]);

        EncryptedDnsProvisioningAttribute attribute = Assert.Single(response.Attributes);
        Assert.Equal(EncryptedDnsProvisioningAddressFamily.Ip4, attribute.AddressFamily);
        Assert.Equal("resolver.example.", attribute.AuthenticationDomainName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0060")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0060_ReplyAddressListContainsAtLeastOneIpAddress()
    {
        Assert.Equal(1, CreateIpv4Reply(IPAddress.Parse("192.0.2.53")).AddressCount);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponseOptions.Create(
                [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)]));
    }

    [Fact]
    [Requirement("RFC9464-S4-P5-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S4P5S3_ServiceParametersIncludeAlpnByDefault()
    {
        EncryptedDnsProvisioningAttribute reply = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));

        Assert.Contains("alpn", reply.ServiceParameterKeys);
        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4ReplyWithoutAlpn(IPAddress.Parse("192.0.2.53"))]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0062")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0062_ResponderMayIgnoreSuggestedValues()
    {
        EncryptedDnsProvisioningAttribute suggested = EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "suggested.example",
            [IPAddress.Parse("192.0.2.100")]);
        EncryptedDnsProvisioningAttribute configured = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));

        EncryptedDnsProvisioningAttribute reply = Assert.Single(CreateReply([suggested], [configured]).Attributes);

        Assert.Equal("resolver.example.", reply.AuthenticationDomainName);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(reply.Addresses));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0063")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0063_MultipleInstancesMayBeReturnedForDistinctAdns()
    {
        EncryptedDnsProvisioningResponse response = CreateReply(
            [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)],
            [
                CreateIpv4Reply(IPAddress.Parse("192.0.2.53"), priority: 10, authenticationDomainName: "primary.example"),
                CreateIpv4Reply(IPAddress.Parse("192.0.2.54"), priority: 20, authenticationDomainName: "secondary.example"),
            ]);

        Assert.Equal(["primary.example.", "secondary.example."], response.Attributes.Select(static attribute => attribute.AuthenticationDomainName).ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0064")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0064_ReplyInstancesAreOrderedBySmallerServicePriorityFirst()
    {
        EncryptedDnsProvisioningResponse response = CreateReply(
            [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)],
            [
                CreateIpv4Reply(IPAddress.Parse("192.0.2.54"), priority: 30, authenticationDomainName: "third.example"),
                CreateIpv4Reply(IPAddress.Parse("192.0.2.53"), priority: 10, authenticationDomainName: "first.example"),
                CreateIpv4Reply(IPAddress.Parse("192.0.2.55"), priority: 20, authenticationDomainName: "second.example"),
            ]);

        Assert.Equal([10, 20, 30], response.Attributes.Select(static attribute => attribute.ServicePriority).ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0065")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0065_ResponderMayReturnDigestInfo()
    {
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo = CreateDigestInfo([0x30, 0x03, 0x01, 0x02, 0x03]);

        EncryptedDnsProvisioningResponse included = CreateReply(
            [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)],
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            digestInfo);
        EncryptedDnsProvisioningResponse omitted = EncryptedDnsProvisioningResponder.CreateReply(
            [EncryptedDnsProvisioningAttribute.CreateEmpty(EncryptedDnsProvisioningPayloadType.Request, EncryptedDnsProvisioningAddressFamily.Ip4)],
            EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))], digestInfo, includeDigestInfo: false));

        Assert.Same(digestInfo, included.DigestInfo);
        Assert.Null(omitted.DigestInfo);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0066_ClientPrefersEncryptedDnsWhenEncryptedAndCleartextResolversExist()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")]);

        Assert.True(plan.UsesEncryptedDnsResolvers);
        Assert.True(plan.HasCleartextDnsResolvers);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(plan.EncryptedResolverEndpoints).Address);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0067")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0067_ClientPlansEncryptedSessionsToConveyedAddresses()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53")), CreateIpv4Reply(IPAddress.Parse("192.0.2.54"), priority: 20)]);

        Assert.Equal([IPAddress.Parse("192.0.2.53"), IPAddress.Parse("192.0.2.54")], plan.EncryptedResolverEndpoints.Select(static endpoint => endpoint.Address).ToArray());
        Assert.All(plan.EncryptedResolverEndpoints, static endpoint => Assert.Equal("resolver.example.", endpoint.AuthenticationDomainName));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0068")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0068_ClientAuthenticatesResolverCertificateUsingAdn()
    {
        EncryptedDnsProvisioningResolverEndpoint endpoint = CreateEndpoint(IPAddress.Parse("192.0.2.53"));

        Assert.Equal(
            EncryptedDnsProvisioningCertificateValidationStatus.ValidatedByAuthenticationDomainName,
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                endpoint,
                digestInfo: null,
                subjectPublicKeyInfoDer: [0x30, 0x01, 0x00],
                authenticationDomainNameMatchesCertificate: true));
        Assert.Equal(
            EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure,
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                endpoint,
                digestInfo: null,
                subjectPublicKeyInfoDer: [0x30, 0x01, 0x00],
                authenticationDomainNameMatchesCertificate: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0069")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0069_ClientCreatesSpkiHashUsingNegotiatedDigestAlgorithm()
    {
        byte[] subjectPublicKeyInfo = [0x30, 0x03, 0x01, 0x02, 0x03];
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo = CreateDigestInfo(subjectPublicKeyInfo);

        Assert.Equal(
            EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfo),
            digestInfo.CertificateDigest.ToArray());
        Assert.Equal(
            EncryptedDnsProvisioningCertificateValidationStatus.ValidatedBySubjectPublicKeyInfoDigest,
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                CreateEndpoint(IPAddress.Parse("192.0.2.53")),
                digestInfo,
                subjectPublicKeyInfo,
                authenticationDomainNameMatchesCertificate: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0070")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0070_MatchingDigestValidatesEncryptedResolverCertificate()
    {
        byte[] subjectPublicKeyInfo = [0x30, 0x03, 0x01, 0x02, 0x03];

        Assert.Equal(
            EncryptedDnsProvisioningCertificateValidationStatus.ValidatedBySubjectPublicKeyInfoDigest,
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                CreateEndpoint(IPAddress.Parse("192.0.2.53")),
                CreateDigestInfo(subjectPublicKeyInfo),
                subjectPublicKeyInfo,
                authenticationDomainNameMatchesCertificate: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0071")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0071_CertificateValidationFailureIsNonRecoverable()
    {
        EncryptedDnsProvisioningResolverEndpoint endpoint = CreateEndpoint(IPAddress.Parse("192.0.2.53"));
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo = CreateDigestInfo([0x30, 0x03, 0x01, 0x02, 0x03]);

        Assert.Equal(
            EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure,
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                endpoint,
                digestInfo,
                subjectPublicKeyInfoDer: [0x30, 0x03, 0x03, 0x02, 0x01],
                authenticationDomainNameMatchesCertificate: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0072")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0072_SplitTunnelInternalNamesUseEncryptedDnsResolvers()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            internalDnsDomains: ["corp.example"],
            splitTunnel: true);

        Assert.True(plan.UsesEncryptedDnsForInternalDomains);
        Assert.Equal(["corp.example."], plan.InternalDnsDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0073")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0073_InternalDnsDomainMayAppearWithoutClassicDnsResolvers()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            cleartextResolverAddresses: [],
            internalDnsDomains: ["corp.example"],
            splitTunnel: true);

        Assert.False(plan.HasCleartextDnsResolvers);
        Assert.True(plan.UsesEncryptedDnsForInternalDomains);
    }

    [Fact]
    [Requirement("RFC9464-S6-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S6P3_NullAuthenticatedResponderRequiresPreconfiguration()
    {
        EncryptedDnsProvisioningClientPlan blocked = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: false);
        EncryptedDnsProvisioningClientPlan allowed = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: true);

        Assert.True(blocked.BlockedByNullAuthentication);
        Assert.False(blocked.UsesEncryptedDnsResolvers);
        Assert.False(allowed.BlockedByNullAuthentication);
        Assert.True(allowed.UsesEncryptedDnsResolvers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0077_ExchangePlannerBindsRequestReplyAndClientPlanDeterministically()
    {
        EncryptedDnsProvisioningConfigurationPayload request =
            EncryptedDnsProvisioningExchangePlanner.CreateSupportRequest(
                includeIpv4: true,
                includeIpv6: false,
                digestHashAlgorithmIdentifiers: [EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier]);
        EncryptedDnsProvisioningConfigurationPayload reply =
            EncryptedDnsProvisioningExchangePlanner.CreateReply(
                request,
                EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))]));
        EncryptedDnsProvisioningClientPlan plan =
            EncryptedDnsProvisioningExchangePlanner.CreateClientPlan(
                reply,
                cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")],
                internalDnsDomains: ["corp.example"],
                splitTunnel: true);

        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, request.PayloadType);
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Reply, reply.PayloadType);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), Assert.Single(plan.EncryptedResolverEndpoints).Address);
        Assert.True(plan.UsesEncryptedDnsForInternalDomains);
    }

    private static EncryptedDnsProvisioningResponse CreateReply(
        IEnumerable<EncryptedDnsProvisioningAttribute> requests,
        IEnumerable<EncryptedDnsProvisioningAttribute> replies,
        EncryptedDnsProvisioningDigestInfoAttribute? digestInfo = null)
    {
        return EncryptedDnsProvisioningResponder.CreateReply(
            requests,
            EncryptedDnsProvisioningResponseOptions.Create(replies, digestInfo));
    }

    private static EncryptedDnsProvisioningResolverEndpoint CreateEndpoint(IPAddress address)
    {
        return EncryptedDnsProvisioningClientPolicy.CreatePlan([CreateIpv4Reply(address)])
            .EncryptedResolverEndpoints.Single();
    }

    private static EncryptedDnsProvisioningDigestInfoAttribute CreateDigestInfo(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        return EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfo));
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4Reply(
        IPAddress address,
        ushort priority = 1,
        string authenticationDomainName = "resolver.example")
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            authenticationDomainName,
            [address],
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'d', (byte)'o', (byte)'q'])],
            priority);
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4ReplyWithoutAlpn(IPAddress address)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressList(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [address]);
    }
}
