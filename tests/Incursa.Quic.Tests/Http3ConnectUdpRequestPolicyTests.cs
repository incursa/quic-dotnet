// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpRequestPolicyTests
{
    [Fact]
    public void Http3RequestBuilder_UsesConnectUdpExtendedConnectAndCapsuleProtocol()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example:8443/masque/{target_host}/{target_port}/?token=abc");

        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, new Http3ConnectUdpTarget("192.0.2.1", 53));

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == Http3ConnectUdp.ProtocolToken);
        Assert.Contains(headers, header => header.Name == ":scheme" && header.Value == "https");
        Assert.Contains(headers, header => header.Name == ":authority" && header.Value == "proxy.example:8443");
        Assert.Contains(headers, header => header.Name == ":path" && header.Value == "/masque/192.0.2.1/53/?token=abc");
        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse(headers));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0022")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_IncludesCapsuleProtocolHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse(headers));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0023")]
    [Requirement("REQ-QUIC-RFC9298-0066")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_IncludesConnectUdpProtocolToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == Http3ConnectUdp.ProtocolToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestValidator_AcceptsRequestsWithoutMessageContent()
    {
        Http3HeaderValidationResult result = Http3ConnectUdp.ValidateHttp3RequestHeaders(ValidRequestHeaders(), contentLength: 0);

        Assert.Equal("CONNECT", result.Method);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesConnectMethod()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0067")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesUdpProxyAuthority()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example:8443/masque/{target_host}/{target_port}/");

        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, new Http3ConnectUdpTarget("example.com", 443));

        Assert.Contains(headers, header => header.Name == ":authority" && header.Value == "proxy.example:8443");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0068")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_UsesNonEmptySchemeAndPath()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":scheme" && !string.IsNullOrEmpty(header.Value));
        Assert.Contains(headers, header => header.Name == ":path" && !string.IsNullOrEmpty(header.Value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0069")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3RequestBuilder_PopulatesSchemeAndPathFromTemplate()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/masque/{target_host}/{target_port}/?token=abc");

        IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, new Http3ConnectUdpTarget("192.0.2.1", 53));

        Assert.Contains(headers, header => header.Name == ":scheme" && header.Value == "https");
        Assert.Contains(headers, header => header.Name == ":path" && header.Value == "/masque/192.0.2.1/53/?token=abc");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0023")]
    [Requirement("REQ-QUIC-RFC9298-0066")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsRequestsWithoutConnectUdpToken()
    {
        QPackFieldLine[] headers =
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ExtendedConnect.WebSocketProtocol),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "proxy.example"),
            new QPackFieldLine(":path", "/masque/example.com/443/"),
            Http3CapsuleProtocol.CreateCapsuleProtocolHeader(),
        ];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0065")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsNonConnectMethod()
    {
        QPackFieldLine[] headers = ReplaceHeader(ValidRequestHeaders(), ":method", "GET");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0068")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(":scheme", "")]
    [InlineData(":path", "")]
    public void Http3RequestValidator_RejectsEmptySchemeOrPath(string headerName, string value)
    {
        QPackFieldLine[] headers = ReplaceHeader(ValidRequestHeaders(), headerName, value);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0067")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsAuthorityOutsideTemplateProxyAuthority()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        Http3ConnectUdpTarget target = new("example.com", 443);
        QPackFieldLine[] headers = ReplaceHeader(Http3ConnectUdp.BuildHttp3RequestHeaders(template, target), ":authority", "other.example");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers, template, target));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0069")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsSchemeOrPathOutsideTemplateExpansion()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/masque/{target_host}/{target_port}/");
        Http3ConnectUdpTarget target = new("example.com", 443);
        QPackFieldLine[] headers = ReplaceHeader(Http3ConnectUdp.BuildHttp3RequestHeaders(template, target), ":path", "/wrong/example.com/443/");

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers, template, target));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0022")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http3RequestValidator_RejectsRequestsWithoutCapsuleProtocol()
    {
        QPackFieldLine[] headers =
        [
            new QPackFieldLine(":method", "CONNECT"),
            new QPackFieldLine(":protocol", Http3ConnectUdp.ProtocolToken),
            new QPackFieldLine(":scheme", "https"),
            new QPackFieldLine(":authority", "proxy.example"),
            new QPackFieldLine(":path", "/masque/example.com/443/"),
        ];

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0034")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(1UL)]
    [InlineData(8UL)]
    public void Http3RequestValidator_RejectsMessageContent(ulong contentLength)
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers, contentLength));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0035")]
    [Requirement("REQ-QUIC-RFC9298-0070")]
    [Requirement("REQ-QUIC-RFC9298-0071")]
    [Requirement("REQ-QUIC-RFC9298-0072")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http3ResponseValidator_Accepts2xxCapsuleResponseWithoutContent()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", "200")];

        Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders);

        Assert.True(Http3ConnectUdp.CanProceedAfterHttp3Response(200, requestHeaders, responseHeaders));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0035")]
    [Requirement("REQ-QUIC-RFC9298-0070")]
    [Requirement("REQ-QUIC-RFC9298-0071")]
    [Requirement("REQ-QUIC-RFC9298-0072")]
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

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, responseHeaders));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.False(Http3ConnectUdp.CanProceedAfterHttp3Response(statusCode, requestHeaders, responseHeaders));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0035")]
    [Requirement("REQ-QUIC-RFC9298-0071")]
    [Requirement("REQ-QUIC-RFC9298-0072")]
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

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.False(Http3ConnectUdp.CanProceedAfterHttp3Response(200, requestHeaders, responseHeaders));
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectUdp.BuildHttp3RequestHeaders(
            Http3ConnectUdpUriTemplate.CreateDefault("proxy.example"),
            new Http3ConnectUdpTarget("example.com", 443));
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
