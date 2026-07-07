// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_Http11UpgradePolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0042")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeMethodIsGet()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ValidRequestHeaders());

        foreach (string method in new[] { "POST", "CONNECT", "get" })
        {
            AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest(method, ValidRequestHeaders()));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0043")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeRequestIncludesSingleHostHeader()
    {
        QPackFieldLine host = Assert.Single(ValidRequestHeaders(), header => header.Name == "host");

        Assert.Equal("proxy.example:8443", host.Value);
        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("host")));
        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", [.. ValidRequestHeaders(), new QPackFieldLine("host", "proxy.example:8443")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0044")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeRequestIncludesCaseInsensitiveConnectionUpgrade()
    {
        foreach (string value in new[] { "Upgrade", "upgrade", "keep-alive, Upgrade" })
        {
            Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ReplaceHeader(ValidRequestHeaders(), "connection", value));
        }

        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0045")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeRequestIncludesConnectIpUpgradeHeader()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ReplaceHeader(ValidRequestHeaders(), "upgrade", "CONNECT-IP"));

        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("upgrade")));
        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ReplaceHeader(ValidRequestHeaders(), "upgrade", "connect-udp")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0046")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedHttp11UpgradeRequestProducesValidationError()
    {
        foreach (IReadOnlyList<QPackFieldLine> headers in new[]
        {
            RequestHeadersWithout("host"),
            RequestHeadersWithout("connection"),
            RequestHeadersWithout("upgrade"),
            [.. ValidRequestHeaders(), new QPackFieldLine("content-length", "1")],
        })
        {
            AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", headers));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0047")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedHttp11UpgradeRequestRecommendsBadRequestStatus()
    {
        Assert.Equal(400, Http3ConnectIpHttp11UpgradePolicy.MalformedRequestStatusCode);
        Assert.NotEqual(101, Http3ConnectIpHttp11UpgradePolicy.MalformedRequestStatusCode);
        Assert.NotEqual(200, Http3ConnectIpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0048")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeResponseStatusIsSwitchingProtocols()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders());

        foreach (int statusCode in new[] { 100, 200, 204, 400 })
        {
            AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(statusCode, ValidResponseHeaders()));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0049")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeResponseIncludesCaseInsensitiveConnectionUpgrade()
    {
        foreach (string value in new[] { "Upgrade", "upgrade", "keep-alive, Upgrade" })
        {
            Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ReplaceHeader(ValidResponseHeaders(), "connection", value));
        }

        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ResponseHeadersWithout("connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0050")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeResponseIncludesSingleConnectIpUpgradeHeader()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ReplaceHeader(ValidResponseHeaders(), "upgrade", "CONNECT-IP"));

        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ResponseHeadersWithout("upgrade")));
        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. ValidResponseHeaders(), new QPackFieldLine("upgrade", "connect-ip")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0051")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http11UpgradeResponseStartsCapsuleProtocolWithoutContent()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 0);

        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 1));
        AssertMessageError(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. ValidResponseHeaders(), new QPackFieldLine("content-type", "application/octet-stream")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0052")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FailedHttp11ProxyingAttemptClosesConnection()
    {
        Assert.False(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(101, ValidResponseHeaders()));
        Assert.True(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(200, ValidResponseHeaders()));
        Assert.True(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(101, ResponseHeadersWithout("upgrade")));
        Assert.True(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(101, ValidResponseHeaders(), contentLength: 1));
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectIpHttp11UpgradePolicy.BuildUpgradeRequestHeaders("proxy.example:8443");
    }

    private static IReadOnlyList<QPackFieldLine> ValidResponseHeaders()
    {
        return Http3ConnectIpHttp11UpgradePolicy.BuildSwitchingProtocolsResponseHeaders();
    }

    private static IReadOnlyList<QPackFieldLine> RequestHeadersWithout(string name)
    {
        return ValidRequestHeaders().Where(header => header.Name != name).ToArray();
    }

    private static IReadOnlyList<QPackFieldLine> ResponseHeadersWithout(string name)
    {
        return ValidResponseHeaders().Where(header => header.Name != name).ToArray();
    }

    private static IReadOnlyList<QPackFieldLine> ReplaceHeader(IReadOnlyList<QPackFieldLine> headers, string name, string value)
    {
        QPackFieldLine[] replaced = new QPackFieldLine[headers.Count];
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            replaced[index] = header.Name == name ? new QPackFieldLine(name, value) : header;
        }

        return replaced;
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);
        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
