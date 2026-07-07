// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_TunnelSetupFuzzClosure
{
    [Fact]
    [Requirement("RFC9298-S3-1-P2-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyExtractsDecodedTargetAndOpensUdpSocketEndpoint()
    {
        foreach ((Http3ConnectUdpUriTemplate template, Http3ConnectUdpTarget target, IPAddress? resolvedAddress) in TargetCases())
        {
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, target);

            Http3ConnectUdpTarget extracted = Http3ConnectUdpTunnelSetupPolicy.ExtractTarget(headers, template);
            IPEndPoint endpoint = Http3ConnectUdpTunnelSetupPolicy.CreateUdpSocketEndpoint(extracted, resolvedAddress);

            Assert.Equal(target.Host, extracted.Host);
            Assert.Equal(target.Port, extracted.Port);
            Assert.Equal(target.Port, endpoint.Port);
            Assert.Equal(resolvedAddress ?? IPAddress.Parse(target.Host), endpoint.Address);
        }

        Http3ConnectUdpUriTemplate expectedTemplate = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        Http3ConnectUdpUriTemplate otherTemplate = Http3ConnectUdpUriTemplate.Create("https://proxy.example/masque/{target_host}/{target_port}/");
        IReadOnlyList<QPackFieldLine> mismatchedHeaders = Http3ConnectUdp.BuildHttp3RequestHeaders(otherTemplate, new Http3ConnectUdpTarget("192.0.2.44", 443));

        AssertMessageError(() => Http3ConnectUdpTunnelSetupPolicy.ExtractTarget(mismatchedHeaders, expectedTemplate));
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyRespondsWithoutWaitingForTargetPacket()
    {
        foreach (Http3ConnectUdpTarget target in new[]
        {
            new Http3ConnectUdpTarget("192.0.2.44", 443),
            new Http3ConnectUdpTarget("2001:db8::10", 443),
        })
        {
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
                target,
                dnsResolutionCompleted: false,
                udpSocketOpened: true,
                receivedPacketFromTarget: false));
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
                target,
                dnsResolutionCompleted: false,
                udpSocketOpened: true,
                receivedPacketFromTarget: true));
        }
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnsTargetRequiresResolutionBeforeResponse()
    {
        Http3ConnectUdpTarget dnsTarget = new("target.example", 443);
        Http3ConnectUdpTarget regNameTarget = new("service.example", 53);

        foreach (Http3ConnectUdpTarget target in new[] { dnsTarget, regNameTarget })
        {
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(target));
            Assert.False(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
                target,
                dnsResolutionCompleted: false,
                udpSocketOpened: true,
                receivedPacketFromTarget: false));
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.CanSendSuccessfulResponse(
                target,
                dnsResolutionCompleted: true,
                udpSocketOpened: true,
                receivedPacketFromTarget: false));
        }
    }

    [Fact]
    [Requirement("RFC9298-S3-1-P4-S5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SetupErrorsRejectRequest()
    {
        foreach ((bool dnsResolutionFailed, bool udpSocketOpenFailed) in new[]
        {
            (true, false),
            (false, true),
            (true, true),
        })
        {
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.ShouldRejectSetup(dnsResolutionFailed, udpSocketOpenFailed));
        }

        Assert.False(Http3ConnectUdpTunnelSetupPolicy.ShouldRejectSetup(dnsResolutionFailed: false, udpSocketOpenFailed: false));
        AssertMessageError(() => Http3ConnectUdpTunnelSetupPolicy.CreateUdpSocketEndpoint(new Http3ConnectUdpTarget("target.example", 443)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0040")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SetupErrorsCanCarryProxyStatusDetails()
    {
        foreach (string errorType in new[] { "dns_error", "connection_refused", "destination_ip_prohibited" })
        {
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdpTunnelSetupPolicy.BuildSetupErrorResponseHeaders(errorType);

            Assert.Contains(headers, header => header.Name == ":status" && header.Value == "502");
            Assert.Contains(headers, header => header.Name == "proxy-status" && header.Value == $"error={errorType}");
        }

        Assert.Throws<ArgumentException>(() => Http3ConnectUdpTunnelSetupPolicy.CreateSetupErrorProxyStatusHeader(""));
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpTunnelSetupPolicy.CreateSetupErrorProxyStatusHeader(" "));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0049")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientAbortsOnAnyNonSuccessfulResponse()
    {
        foreach (int statusCode in new[] { 100, 101, 199, 300, 400, 502, 599 })
        {
            Assert.True(Http3ConnectUdpTunnelSetupPolicy.ShouldAbortRequestOnResponse(statusCode));
        }

        foreach (int statusCode in new[] { 200, 201, 204, 299 })
        {
            Assert.False(Http3ConnectUdpTunnelSetupPolicy.ShouldAbortRequestOnResponse(statusCode));
        }
    }

    private static (Http3ConnectUdpUriTemplate Template, Http3ConnectUdpTarget Target, IPAddress? ResolvedAddress)[] TargetCases()
    {
        return
        [
            (Http3ConnectUdpUriTemplate.CreateDefault("proxy.example"), new Http3ConnectUdpTarget("192.0.2.44", 443), null),
            (Http3ConnectUdpUriTemplate.Create("https://proxy.example:8443/masque/{target_host}/{target_port}/?token=abc"), new Http3ConnectUdpTarget("2001:db8::10", 443), null),
            (Http3ConnectUdpUriTemplate.Create("https://proxy.example/connect/{target_port}/{target_host}"), new Http3ConnectUdpTarget("target.example", 53), IPAddress.Parse("203.0.113.53")),
        ];
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
