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
    [Requirement("RFC9484-S4-P3-S1-R01")]
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
    [Requirement("RFC9484-S4-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestPolicy_RejectsExpansionWithUnresolvedVariables()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{tenant}");

        Assert.Throws<ArgumentException>(() => Http3ConnectIpRequestPolicy.ExpandRequestTarget(template, "host.example"));
    }

    [Theory]
    [Requirement("RFC9484-S4-P5-S1-R01")]
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
    [Requirement("RFC9484-S4-P5-S1-R01")]
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

    [Fact]
    [Requirement("RFC9484-S4-4-P1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesExtendedConnect()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == Http3ConnectIpFoundationPolicy.ProtocolToken);
    }

    [Fact]
    [Requirement("RFC9484-S4-4-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerPolicy_RequiresExtendedConnectSetting()
    {
        Assert.True(Http3ConnectIp.ServerMustSendExtendedConnectSetting);
    }

    [Fact]
    [Requirement("RFC9484-S4-4-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerPolicy_DoesNotAllowOmittingExtendedConnectSetting()
    {
        Assert.False(!Http3ConnectIp.ServerMustSendExtendedConnectSetting);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0055")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesConnectMethod()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsNonConnectMethod()
    {
        QPackFieldLine[] headers = ReplaceHeader(ValidRequestHeaders(), ":method", "GET");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0056")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesConnectIpProtocolToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == Http3ConnectIpFoundationPolicy.ProtocolToken);
    }

    [Fact]
    [Requirement("RFC9484-S4-4-P1-R01")]
    [Requirement("REQ-QUIC-RFC9484-0056")]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsRequestsWithoutConnectIpToken()
    {
        QPackFieldLine[] headers = ReplaceHeader(ValidRequestHeaders(), ":protocol", Http3ExtendedConnect.WebSocketProtocol);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0057")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesIpProxyAuthority()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example:8443/masque/{target}/{ipproto}/");

        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "tcp");

        Assert.Contains(headers, header => header.Name == ":authority" && header.Value == "proxy.example:8443");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0057")]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsAuthorityOutsideTemplateProxyAuthority()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault("proxy.example");
        QPackFieldLine[] headers = ReplaceHeader(Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp"), ":authority", "other.example");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers, template, "192.0.2.1", "udp"));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0058")]
    [Requirement("REQ-QUIC-RFC9484-0059")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesNonEmptySchemeAndPath()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":scheme" && !string.IsNullOrEmpty(header.Value));
        Assert.Contains(headers, header => header.Name == ":path" && !string.IsNullOrEmpty(header.Value));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0058")]
    [Requirement("REQ-QUIC-RFC9484-0059")]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(":scheme", "")]
    [InlineData(":path", "")]
    public void Http3RequestValidator_RejectsEmptySchemeOrPath(string headerName, string value)
    {
        QPackFieldLine[] headers = ReplaceHeader(ValidRequestHeaders(), headerName, value);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0060")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_PopulatesSchemeAndPathFromTemplateExpansion()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/masque/{target}/{ipproto}/?token=abc");

        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp");

        Assert.Contains(headers, header => header.Name == ":scheme" && header.Value == "https");
        Assert.Contains(headers, header => header.Name == ":path" && header.Value == "/masque/192.0.2.1/udp/?token=abc");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0060")]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsSchemeOrPathOutsideTemplateExpansion()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/masque/{target}/{ipproto}/");
        QPackFieldLine[] headers = ReplaceHeader(Http3ConnectIp.BuildHttp3RequestHeaders(template, "192.0.2.1", "udp"), ":path", "/wrong/192.0.2.1/udp/");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers, template, "192.0.2.1", "udp"));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsRequestsWithoutCapsuleProtocol()
    {
        QPackFieldLine[] headers =
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ConnectIpFoundationPolicy.ProtocolToken),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "proxy.example"),
            new QPackFieldLine(":path", "/masque/192.0.2.1/udp/"),
        ];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestValidator_AcceptsConformingRequest()
    {
        Http3HeaderValidationResult result = Http3ConnectIp.ValidateHttp3RequestHeaders(ValidRequestHeaders());

        Assert.Equal("CONNECT", result.Method);
        Assert.Equal(Http3ConnectIpFoundationPolicy.ProtocolToken, result.Protocol);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(1UL)]
    [InlineData(8UL)]
    public void Http3RequestValidator_RejectsMessageContent(ulong contentLength)
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateHttp3RequestHeaders(headers, contentLength));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0062")]
    [Requirement("REQ-QUIC-RFC9484-0063")]
    [Requirement("REQ-QUIC-RFC9484-0064")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3ResponseValidator_Accepts2xxCapsuleResponseWithoutContent()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", "200")];

        Http3ConnectIp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders);

        Assert.True(Http3ConnectIp.CanProceedAfterHttp3Response(200, requestHeaders, responseHeaders));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0062")]
    [Requirement("REQ-QUIC-RFC9484-0063")]
    [Requirement("REQ-QUIC-RFC9484-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(101)]
    [InlineData(204)]
    [InlineData(206)]
    [InlineData(404)]
    public void Http3ResponseValidator_RejectsNonSuccessfulOrContentBearingStatuses(int statusCode)
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture))];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, responseHeaders));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.False(Http3ConnectIp.CanProceedAfterHttp3Response(statusCode, requestHeaders, responseHeaders));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0063")]
    [Requirement("REQ-QUIC-RFC9484-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3ResponseValidator_RejectsSuccessfulResponsesWithMessageContent()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders =
        [
            new QPackFieldLine(":status", "200"),
            new QPackFieldLine("content-length", "1"),
        ];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.False(Http3ConnectIp.CanProceedAfterHttp3Response(200, requestHeaders, responseHeaders));
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
}
