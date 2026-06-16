// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsProvisioningClientPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0050")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MalformedProvisioningAttributesAreRejectedBeforePolicyUse()
    {
        byte[] malformed = [0x00, 0x1B, 0x00, 0x05, 0x00];

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, malformed));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0050")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WellFormedProvisioningAttributesDecodeForPolicyUse()
    {
        EncryptedDnsProvisioningAttribute attribute = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));

        EncryptedDnsProvisioningAttribute decoded =
            EncryptedDnsProvisioningAttribute.Decode(EncryptedDnsProvisioningPayloadType.Reply, attribute.Encode());

        Assert.Equal(attribute.AuthenticationDomainName, decoded.AuthenticationDomainName);
        Assert.Equal(attribute.Addresses, decoded.Addresses);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0066")]
    [Requirement("REQ-QUIC-RFC9464-0067")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PlanPrefersEncryptedResolversAndUsesConveyedAddresses()
    {
        IPAddress lowerPriority = IPAddress.Parse("192.0.2.54");
        IPAddress higherPriority = IPAddress.Parse("192.0.2.53");

        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [
                CreateIpv4Reply(lowerPriority, priority: 20),
                CreateIpv4Reply(higherPriority, priority: 10),
            ],
            cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")]);

        Assert.True(plan.UsesEncryptedDnsResolvers);
        Assert.True(plan.HasCleartextDnsResolvers);
        Assert.Equal([higherPriority, lowerPriority], plan.EncryptedResolverEndpoints.Select(static endpoint => endpoint.Address).ToArray());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0066")]
    [Requirement("REQ-QUIC-RFC9464-0067")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PlanWithoutEncryptedResolversDoesNotInventEncryptedSessionTargets()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [],
            cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")]);

        Assert.False(plan.UsesEncryptedDnsResolvers);
        Assert.Empty(plan.EncryptedResolverEndpoints);
        Assert.True(plan.HasCleartextDnsResolvers);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0068")]
    [Requirement("REQ-QUIC-RFC9464-0069")]
    [Requirement("REQ-QUIC-RFC9464-0070")]
    [Requirement("REQ-QUIC-RFC9464-0071")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DigestMatchValidatesResolverCertificate()
    {
        EncryptedDnsProvisioningResolverEndpoint endpoint = CreateEndpoint();
        byte[] subjectPublicKeyInfo = [0x30, 0x03, 0x01, 0x02, 0x03];
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo = CreateDigestInfo(subjectPublicKeyInfo);

        EncryptedDnsProvisioningCertificateValidationStatus status =
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                endpoint,
                digestInfo,
                subjectPublicKeyInfo,
                authenticationDomainNameMatchesCertificate: false);

        Assert.Equal(EncryptedDnsProvisioningCertificateValidationStatus.ValidatedBySubjectPublicKeyInfoDigest, status);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0068")]
    [Requirement("REQ-QUIC-RFC9464-0069")]
    [Requirement("REQ-QUIC-RFC9464-0070")]
    [Requirement("REQ-QUIC-RFC9464-0071")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DigestMismatchMakesResolverCertificateFailureNonRecoverable()
    {
        EncryptedDnsProvisioningResolverEndpoint endpoint = CreateEndpoint();
        EncryptedDnsProvisioningDigestInfoAttribute digestInfo = CreateDigestInfo([0x30, 0x03, 0x01, 0x02, 0x03]);

        EncryptedDnsProvisioningCertificateValidationStatus status =
            EncryptedDnsProvisioningClientPolicy.ValidateResolverCertificate(
                endpoint,
                digestInfo,
                [0x30, 0x03, 0x03, 0x02, 0x01],
                authenticationDomainNameMatchesCertificate: true);

        Assert.Equal(EncryptedDnsProvisioningCertificateValidationStatus.NonRecoverableFailure, status);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0072")]
    [Requirement("REQ-QUIC-RFC9464-0073")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SplitTunnelInternalDomainsUseEncryptedResolversWithoutClassicDnsPrerequisite()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            internalDnsDomains: ["corp.example"],
            splitTunnel: true);

        Assert.True(plan.UsesEncryptedDnsResolvers);
        Assert.False(plan.HasCleartextDnsResolvers);
        Assert.True(plan.UsesEncryptedDnsForInternalDomains);
        Assert.Equal(["corp.example."], plan.InternalDnsDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0072")]
    [Requirement("REQ-QUIC-RFC9464-0073")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonSplitTunnelPlanDoesNotRouteInternalDomainsBySplitTunnelPolicy()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            internalDnsDomains: ["corp.example"],
            splitTunnel: false);

        Assert.True(plan.UsesEncryptedDnsResolvers);
        Assert.False(plan.UsesEncryptedDnsForInternalDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0076")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NullAuthenticatedResponderBlocksEncryptedDnsUnlessPreconfigured()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: false);

        Assert.True(plan.BlockedByNullAuthentication);
        Assert.False(plan.UsesEncryptedDnsResolvers);
        Assert.Empty(plan.EncryptedResolverEndpoints);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0076")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PreconfiguredNullAuthenticatedResponderCanUseEncryptedDns()
    {
        EncryptedDnsProvisioningClientPlan plan = EncryptedDnsProvisioningClientPolicy.CreatePlan(
            [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
            responderUsedNullAuthentication: true,
            nullAuthenticationPreconfigured: true);

        Assert.False(plan.BlockedByNullAuthentication);
        Assert.True(plan.UsesEncryptedDnsResolvers);
    }

    private static EncryptedDnsProvisioningResolverEndpoint CreateEndpoint()
    {
        return EncryptedDnsProvisioningClientPolicy.CreatePlan([CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))])
            .EncryptedResolverEndpoints[0];
    }

    private static EncryptedDnsProvisioningDigestInfoAttribute CreateDigestInfo(ReadOnlySpan<byte> subjectPublicKeyInfo)
    {
        return EncryptedDnsProvisioningDigestInfoAttribute.CreateReplyOrSet(
            EncryptedDnsProvisioningPayloadType.Reply,
            authenticationDomainName: null,
            EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier,
            EncryptedDnsProvisioningDigestInfoAttribute.ComputeSha2_256SubjectPublicKeyInfoDigest(subjectPublicKeyInfo));
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4Reply(IPAddress address, ushort priority = 1)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [address],
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'d', (byte)'o', (byte)'q'])],
            priority);
    }
}
