// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_RequestPolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientInitiatesSingleStreamTunnelWithConnectIpUpgradeToken()
    {
        Assert.True(Http3ConnectIpRequestPolicy.CanInitiateIpTunnel("connect-ip", associatedWithSingleHttpStream: true));

        foreach ((string token, bool singleStream) in new[] { ("connect-udp", true), ("connect-ip", false), ("CONNECT-IP", true) })
        {
            Assert.False(Http3ConnectIpRequestPolicy.CanInitiateIpTunnel(token, singleStream));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestPathAndQueryComeFromUriTemplateExpansion()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/masque/{target}/{ipproto}/{tenant}{?token}");
        Dictionary<string, string> variables = new(StringComparer.Ordinal)
        {
            ["tenant"] = "alpha",
            ["token"] = "abc",
        };

        Http3ConnectIpRequestTarget target = Http3ConnectIpRequestPolicy.ExpandRequestTarget(template, "192.0.2.1", "udp", variables);
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp", variables);

        Assert.Equal("/masque/192.0.2.1/udp/alpha?token=abc", target.PathAndQuery);
        Assert.Contains(headers, header => header.Name == ":path" && header.Value == target.PathAndQuery);
    }

    [Fact]
    [Requirement("RFC9484-S4-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyingRequiresTlsQuicOrEquivalentEncryption()
    {
        foreach ((bool tls, bool quic, bool equivalent, bool expected) in new[]
        {
            (true, false, false, true),
            (false, true, false, true),
            (false, false, true, true),
            (false, false, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpRequestPolicy.IsProtectedByRequiredEncryption(tls, quic, equivalent));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConfiguredRecipientForwardsToAnotherHttpServer()
    {
        Assert.Equal(
            Http3ConnectIpRecipientAction.ForwardToConfiguredHttpServer,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnconfiguredRecipientActsAsIpProxy()
    {
        Assert.Equal(
            Http3ConnectIpRecipientAction.ActAsIpProxy,
            Http3ConnectIpRequestPolicy.SelectRecipientAction(configuredToUseAnotherHttpServer: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyMayRejectIpProxyingRequestWithoutRequiringRejection()
    {
        Assert.True(Http3ConnectIpRequestPolicy.IpProxyMayRejectRequest);
        Assert.Equal(Http3ConnectIpRecipientAction.ActAsIpProxy, Http3ConnectIpRequestPolicy.SelectRecipientAction(false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0041")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientAbortsOnAnyNonSuccessfulProxyingResponse()
    {
        foreach ((int statusCode, bool abortExpected) in new[]
        {
            (100, true),
            (199, true),
            (200, false),
            (250, false),
            (299, false),
            (300, true),
            (502, true),
        })
        {
            Assert.Equal(abortExpected, Http3ConnectIpRequestPolicy.ShouldAbortRequestOnResponse(statusCode));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-4-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3IpProxyingRequestsUseExtendedConnect()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == "connect-ip");
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":protocol", "connect-udp")));
    }

    [Fact]
    [Requirement("RFC9484-S4-4-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerPolicyRequiresExtendedConnectSetting()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIp.ServerMustSendExtendedConnectSetting);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0055")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3RequestMethodPseudoHeaderIsConnect()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":method", "GET")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0056")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3RequestProtocolPseudoHeaderIsConnectIp()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == "connect-ip");
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":protocol", "websocket")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0057")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3RequestAuthorityPseudoHeaderContainsIpProxyAuthority()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example:8443/masque/{target}/{ipproto}/");
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp");

        Assert.Contains(headers, header => header.Name == ":authority" && header.Value == "proxy.example:8443");
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":authority", "other.example"), template, "192.0.2.1", "udp"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0058")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3RequestPathPseudoHeaderIsNotEmpty()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":path" && !string.IsNullOrEmpty(header.Value));
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":path", "")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0059")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3RequestSchemePseudoHeaderIsNotEmpty()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":scheme" && !string.IsNullOrEmpty(header.Value));
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":scheme", "")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0060")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3SchemeAndPathMatchCompletedUriTemplateExpansion()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/masque/{target}/{ipproto}/?token=abc");
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp");

        Assert.Contains(headers, header => header.Name == ":scheme" && header.Value == "https");
        Assert.Contains(headers, header => header.Name == ":path" && header.Value == "/masque/192.0.2.1/udp/?token=abc");
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":path", "/wrong/"), template, "192.0.2.1", "udp"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonConformingIpProxyingRequestsAreMalformed()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Equal("CONNECT", Http3ConnectIp.ValidateHttp3RequestHeaders(headers).Method);
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(RemoveHeader(headers, "capsule-protocol")));
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers, contentLength: 1));
        AssertMessageError(() => Http3ConnectIp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":protocol", "connect-udp")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0062")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3ProxyingResponseStatusCodeMustBeInSuccessfulRange()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();

        foreach (int statusCode in new[] { 200, 201, 250, 299 })
        {
            Http3ConnectIp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, [new QPackFieldLine(":status", statusCode.ToString())]);
        }

        foreach (int statusCode in new[] { 101, 199, 300, 404, 502 })
        {
            AssertMessageError(() => Http3ConnectIp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, [new QPackFieldLine(":status", statusCode.ToString())]));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-5-P2-2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SuccessfulResponseStartsCapsuleProtocolWithoutMessageContent()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", "200")];

        Http3ConnectIp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders, responseContentLength: 0);
        AssertMessageError(() => Http3ConnectIp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders, responseContentLength: 1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0064")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FailedProxyingResponsePreventsProceedingAfterHttp3Response()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();

        Assert.True(Http3ConnectIp.CanProceedAfterHttp3Response(200, requestHeaders, [new QPackFieldLine(":status", "200")]));
        Assert.False(Http3ConnectIp.CanProceedAfterHttp3Response(404, requestHeaders, [new QPackFieldLine(":status", "404")]));
        Assert.False(Http3ConnectIp.CanProceedAfterHttp3Response(200, requestHeaders, [new QPackFieldLine(":status", "200")], responseContentLength: 1));
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "192.0.2.1",
            "udp");
    }

    private static QPackFieldLine[] ReplaceHeader(IReadOnlyList<QPackFieldLine> headers, string name, string value)
    {
        QPackFieldLine[] replaced = new QPackFieldLine[headers.Count];
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            replaced[index] = header.Name == name ? new QPackFieldLine(name, value) : header;
        }

        return replaced;
    }

    private static QPackFieldLine[] RemoveHeader(IReadOnlyList<QPackFieldLine> headers, string name)
    {
        return headers.Where(header => header.Name != name).ToArray();
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);
        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
