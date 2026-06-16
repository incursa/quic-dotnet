// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class EncryptedDnsProvisioningExchangePlannerTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExchangePlannerBuildsRequestReplyAndClientPlan()
    {
        EncryptedDnsProvisioningConfigurationPayload request =
            EncryptedDnsProvisioningExchangePlanner.CreateSupportRequest(
                digestHashAlgorithmIdentifiers: [EncryptedDnsProvisioningDigestInfoAttribute.Sha2_256HashAlgorithmIdentifier]);
        EncryptedDnsProvisioningAttribute replyAttribute = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));

        EncryptedDnsProvisioningConfigurationPayload reply =
            EncryptedDnsProvisioningExchangePlanner.CreateReply(
                request,
                EncryptedDnsProvisioningResponseOptions.Create([replyAttribute]));
        EncryptedDnsProvisioningClientPlan plan =
            EncryptedDnsProvisioningExchangePlanner.CreateClientPlan(
                reply,
                cleartextResolverAddresses: [IPAddress.Parse("198.51.100.53")],
                internalDnsDomains: ["corp.example"],
                splitTunnel: true);

        Assert.Equal(EncryptedDnsProvisioningPayloadType.Request, request.PayloadType);
        Assert.NotNull(request.DigestInfo);
        Assert.Equal(EncryptedDnsProvisioningPayloadType.Reply, reply.PayloadType);
        Assert.False(reply.IsEmpty);
        EncryptedDnsProvisioningResolverEndpoint endpoint = Assert.Single(plan.EncryptedResolverEndpoints);
        Assert.Equal(IPAddress.Parse("192.0.2.53"), endpoint.Address);
        Assert.Equal("resolver.example.", endpoint.AuthenticationDomainName);
        Assert.True(plan.HasCleartextDnsResolvers);
        Assert.True(plan.UsesEncryptedDnsForInternalDomains);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ExchangePlannerRejectsReplyPlanningFromNonRequestPayload()
    {
        EncryptedDnsProvisioningConfigurationPayload replyPayload =
            EncryptedDnsProvisioningConfigurationPayload.Create(
                EncryptedDnsProvisioningPayloadType.Reply,
                [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))]);

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningExchangePlanner.CreateReply(
                replyPayload,
                EncryptedDnsProvisioningResponseOptions.Create([CreateIpv4Reply(IPAddress.Parse("192.0.2.54"))])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConfigurationPayloadRejectsMismatchedAttributePayloadTypes()
    {
        EncryptedDnsProvisioningAttribute replyAttribute = CreateIpv4Reply(IPAddress.Parse("192.0.2.53"));

        Assert.Throws<ArgumentException>(() =>
            EncryptedDnsProvisioningConfigurationPayload.Create(
                EncryptedDnsProvisioningPayloadType.Request,
                [replyAttribute]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9464-0077")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ExchangePlannerProducesEmptyClientPlanWhenRequestIsDiscarded()
    {
        EncryptedDnsProvisioningAttribute request = EncryptedDnsProvisioningAttribute.CreateEmpty(
            EncryptedDnsProvisioningPayloadType.Request,
            EncryptedDnsProvisioningAddressFamily.Ip4);
        EncryptedDnsProvisioningConfigurationPayload requestPayload =
            EncryptedDnsProvisioningConfigurationPayload.Create(
                EncryptedDnsProvisioningPayloadType.Request,
                [request, request, request]);

        EncryptedDnsProvisioningConfigurationPayload reply =
            EncryptedDnsProvisioningExchangePlanner.CreateReply(
                requestPayload,
                EncryptedDnsProvisioningResponseOptions.Create(
                    [CreateIpv4Reply(IPAddress.Parse("192.0.2.53"))],
                    duplicateAttributeDiscardThreshold: 1));
        EncryptedDnsProvisioningClientPlan plan =
            EncryptedDnsProvisioningExchangePlanner.CreateClientPlan(reply);

        Assert.True(reply.IsEmpty);
        Assert.False(plan.UsesEncryptedDnsResolvers);
        Assert.Empty(plan.EncryptedResolverEndpoints);
    }

    private static EncryptedDnsProvisioningAttribute CreateIpv4Reply(IPAddress address)
    {
        return EncryptedDnsProvisioningAttribute.CreateAddressListWithServiceParameters(
            EncryptedDnsProvisioningPayloadType.Reply,
            EncryptedDnsProvisioningAddressFamily.Ip4,
            "resolver.example",
            [address],
            [EncryptedDnsProvisioningServiceParameter.Create(EncryptedDnsProvisioningServiceParameter.AlpnKey, [0x02, (byte)'d', (byte)'o', (byte)'q'])]);
    }
}
