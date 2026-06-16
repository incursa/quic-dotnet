// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpRequestPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0025")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestPolicy_InitiatesSingleStreamTunnelWithConnectIpToken()
    {
        Assert.True(Http3ConnectIpRequestPolicy.CanInitiateIpTunnel(
            Http3ConnectIpFoundationPolicy.ProtocolToken,
            associatedWithSingleHttpStream: true));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0025")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("connect-udp", true)]
    [InlineData("connect-ip", false)]
    public void RequestPolicy_RejectsWrongTokenOrMultipleStreamAssociation(string token, bool associatedWithSingleHttpStream)
    {
        Assert.False(Http3ConnectIpRequestPolicy.CanInitiateIpTunnel(token, associatedWithSingleHttpStream));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0026")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestPolicy_ExpandsUriTemplateForRequestPathAndQuery()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}{?ipproto}");

        Http3ConnectIpRequestTarget target = Http3ConnectIpRequestPolicy.ExpandRequestTarget(template, "host.example", "17");

        Assert.Equal("https", target.Scheme);
        Assert.Equal("proxy.example", target.Authority);
        Assert.Equal("/ip/host.example?ipproto=17", target.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0026")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_RejectsExpansionWithUnresolvedVariables()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{tenant}");

        Assert.Throws<ArgumentException>(() => Http3ConnectIpRequestPolicy.ExpandRequestTarget(template, "host.example"));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void RequestPolicy_AcceptsRequiredEncryptionModes(bool tlsProtected, bool quicProtected, bool equivalentEncryptionProtocol)
    {
        Assert.True(Http3ConnectIpRequestPolicy.IsProtectedByRequiredEncryption(
            tlsProtected,
            quicProtected,
            equivalentEncryptionProtocol));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_RejectsUnprotectedHttpProxying()
    {
        Assert.False(Http3ConnectIpRequestPolicy.IsProtectedByRequiredEncryption(
            tlsProtected: false,
            quicProtected: false,
            equivalentEncryptionProtocol: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0028")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestPolicy_ForwardsToConfiguredHttpServer()
    {
        Assert.Equal(
            Http3ConnectIpRecipientAction.ForwardToConfiguredHttpServer,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0028")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_DoesNotForwardWithoutConfiguredHttpServer()
    {
        Assert.NotEqual(
            Http3ConnectIpRecipientAction.ForwardToConfiguredHttpServer,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0029")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestPolicy_ActsAsIpProxyWithoutConfiguredHttpServer()
    {
        Assert.Equal(
            Http3ConnectIpRecipientAction.ActAsIpProxy,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0029")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_DoesNotActAsProxyWhenForwardingConfigured()
    {
        Assert.NotEqual(
            Http3ConnectIpRecipientAction.ActAsIpProxy,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestPolicy_AllowsIpProxyRejection()
    {
        Assert.True(Http3ConnectIpRequestPolicy.IpProxyMayRejectRequest);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_RejectionPermissionDoesNotRequireRejection()
    {
        Assert.Equal(Http3ConnectIpRecipientAction.ActAsIpProxy, Http3ConnectIpRequestPolicy.SelectRecipientAction(false));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0041")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(101)]
    [InlineData(199)]
    [InlineData(300)]
    [InlineData(502)]
    public void RequestPolicy_ClientAbortsOnNonSuccessfulProxyingResponse(int statusCode)
    {
        Assert.True(Http3ConnectIpRequestPolicy.ShouldAbortRequestOnResponse(statusCode));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0041")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(200)]
    [InlineData(204)]
    [InlineData(299)]
    public void RequestPolicy_ClientDoesNotAbortOnSuccessfulProxyingResponse(int statusCode)
    {
        Assert.False(Http3ConnectIpRequestPolicy.ShouldAbortRequestOnResponse(statusCode));
    }
}
