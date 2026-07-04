// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using Incursa.Qpack;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpTunnelSetupPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0036")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_ExtractsDecodedTargetAndUdpSocketEndpoint()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(
            template,
            new Http3ConnectUdpTarget("2001:db8::10", 443));

        Http3ConnectUdpTarget target = Http3ConnectUdpTunnelSetupPolicy.ExtractTarget(headers, template);
        IPEndPoint endpoint = Http3ConnectUdpTunnelSetupPolicy.CreateUdpSocketEndpoint(target);

        Assert.Equal("2001:db8::10", target.Host);
        Assert.Equal(443, target.Port);
        Assert.Equal(IPAddress.Parse("2001:db8::10"), endpoint.Address);
        Assert.Equal(443, endpoint.Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0036")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_RejectsRequestsThatDoNotMatchTemplate()
    {
        Http3ConnectUdpUriTemplate expectedTemplate = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        Http3ConnectUdpUriTemplate differentTemplate = Http3ConnectUdpUriTemplate.Create("https://proxy.example/masque/{target_host}/{target_port}/");
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(
            differentTemplate,
            new Http3ConnectUdpTarget("192.0.2.44", 443));

        Assert.Throws<Http3Exception>(() => Http3ConnectUdpTunnelSetupPolicy.ExtractTarget(headers, expectedTemplate));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0037")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_CanRespondWithoutWaitingForTargetPacket()
    {
        Http3ConnectUdpTarget target = new("192.0.2.44", 443);

        bool withoutPacket = Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
            target,
            dnsResolutionCompleted: true,
            udpSocketOpened: true,
            receivedPacketFromTarget: false);
        bool withPacket = Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
            target,
            dnsResolutionCompleted: true,
            udpSocketOpened: true,
            receivedPacketFromTarget: true);

        Assert.True(withoutPacket);
        Assert.Equal(withoutPacket, withPacket);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotRespondBeforeSocketOpen()
    {
        Http3ConnectUdpTarget target = new("192.0.2.44", 443);

        Assert.False(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
            target,
            dnsResolutionCompleted: true,
            udpSocketOpened: false,
            receivedPacketFromTarget: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_RequiresDnsResolutionBeforeResponseForDnsTargets()
    {
        Http3ConnectUdpTarget target = new("target.example", 443);

        Assert.True(Http3ConnectUdpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(target));
        Assert.False(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
            target,
            dnsResolutionCompleted: false,
            udpSocketOpened: true,
            receivedPacketFromTarget: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotRequireDnsResolutionForIpLiteralTargets()
    {
        Http3ConnectUdpTarget target = new("192.0.2.44", 443);

        Assert.False(Http3ConnectUdpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(target));
        Assert.True(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
            target,
            dnsResolutionCompleted: false,
            udpSocketOpened: true,
            receivedPacketFromTarget: false));
    }

    [Theory]
    [Requirement("RFC9298-S3-1-P4-S5-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void TunnelSetup_RejectsRequestWhenSetupErrorsOccur(bool dnsResolutionFailed, bool udpSocketOpenFailed)
    {
        Assert.True(Http3ConnectUdpTunnelSetupPolicy.ShouldRejectSetup(dnsResolutionFailed, udpSocketOpenFailed));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S5-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotRejectRequestWithoutSetupErrors()
    {
        Assert.False(Http3ConnectUdpTunnelSetupPolicy.ShouldRejectSetup(dnsResolutionFailed: false, udpSocketOpenFailed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0040")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_AddsProxyStatusDetailsOnSetupErrors()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdpTunnelSetupPolicy.BuildSetupErrorResponseHeaders("dns_error");

        Assert.Contains(headers, header => header.Name == ":status" && header.Value == "502");
        Assert.Contains(headers, header => header.Name == "proxy-status" && header.Value == "error=dns_error");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0040")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_RejectsEmptyProxyStatusErrorTypes()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpTunnelSetupPolicy.CreateSetupErrorProxyStatusHeader(""));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0049")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(199)]
    [InlineData(300)]
    [InlineData(502)]
    public void TunnelSetup_ClientAbortsOnNonSuccessResponse(int statusCode)
    {
        Assert.True(Http3ConnectUdpTunnelSetupPolicy.ShouldAbortRequestOnResponse(statusCode));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0049")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(200)]
    [InlineData(204)]
    [InlineData(299)]
    public void TunnelSetup_ClientDoesNotAbortOnSuccessfulResponse(int statusCode)
    {
        Assert.False(Http3ConnectUdpTunnelSetupPolicy.ShouldAbortRequestOnResponse(statusCode));
    }
}
