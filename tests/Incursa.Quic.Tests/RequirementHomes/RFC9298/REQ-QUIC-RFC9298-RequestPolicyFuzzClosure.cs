// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_RequestPolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpTunnelsRequireCapsuleProtocol()
    {
        foreach ((Http3ConnectUdpUriTemplate template, Http3ConnectUdpTarget target) in RequestCases())
        {
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, target);

            Assert.True(Http3CapsuleProtocol.IsCapsuleProtocolInUse(headers));
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(WithoutHeader(headers, Http3CapsuleProtocol.CapsuleProtocolHeaderName)));
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, Http3CapsuleProtocol.CapsuleProtocolHeaderName, "?0")));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientRequestUsesConnectUdpUpgradeToken()
    {
        foreach ((Http3ConnectUdpUriTemplate template, Http3ConnectUdpTarget target) in RequestCases())
        {
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, target);

            Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == Http3ConnectUdp.ProtocolToken);
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":protocol", "websocket")));
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(WithoutHeader(headers, ":protocol")));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyingRequestsCarryNoMessageContent()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Http3ConnectUdp.ValidateHttp3RequestHeaders(headers, contentLength: 0);
        foreach (ulong contentLength in new[] { 1UL, 8UL, 65_535UL })
        {
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(headers, contentLength));
        }

        AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(AppendHeader(headers, new QPackFieldLine("content-length", "1"))));
        AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(AppendHeader(headers, new QPackFieldLine("content-type", "application/octet-stream"))));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0035")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SuccessfulUdpProxyingResponsesCarryNoMessageContent()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", "200")];

        Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders);
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders, responseContentLength: 1));
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(
            200,
            requestHeaders,
            AppendHeader(responseHeaders, new QPackFieldLine("content-length", "1"))));
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(
            200,
            requestHeaders,
            AppendHeader(responseHeaders, new QPackFieldLine("content-type", "application/octet-stream"))));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0065")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MethodPseudoHeaderIsConnect()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":method" && header.Value == "CONNECT");
        foreach (string method in new[] { "GET", "POST", "CONNECT-UDP", "" })
        {
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":method", method)));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtocolPseudoHeaderIsConnectUdp()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":protocol" && header.Value == "connect-udp");
        foreach (string protocol in new[] { "CONNECT-UDP", "connect-ip", "websocket", "" })
        {
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":protocol", protocol)));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0067")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AuthorityPseudoHeaderContainsUdpProxyAuthority()
    {
        foreach ((Http3ConnectUdpUriTemplate template, Http3ConnectUdpTarget target) in RequestCases())
        {
            Http3ConnectUdpRequestTarget expected = template.Expand(target);
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, target);

            Assert.Contains(headers, header => header.Name == ":authority" && header.Value == expected.Authority);
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":authority", "other.example"), template, target));
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":authority", ""), template, target));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0068")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SchemeAndPathPseudoHeadersAreNotEmpty()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == ":scheme" && !string.IsNullOrEmpty(header.Value));
        Assert.Contains(headers, header => header.Name == ":path" && !string.IsNullOrEmpty(header.Value));
        AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":scheme", "")));
        AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":path", "")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0069")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SchemeAndPathComeFromExpandedUriTemplate()
    {
        foreach ((Http3ConnectUdpUriTemplate template, Http3ConnectUdpTarget target) in RequestCases())
        {
            Http3ConnectUdpRequestTarget expected = template.Expand(target);
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectUdp.BuildHttp3RequestHeaders(template, target);

            Assert.Contains(headers, header => header.Name == ":scheme" && header.Value == expected.Scheme);
            Assert.Contains(headers, header => header.Name == ":path" && header.Value == expected.PathAndQuery);
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":scheme", "http"), template, target));
            AssertMessageError(() => Http3ConnectUdp.ValidateHttp3RequestHeaders(ReplaceHeader(headers, ":path", "/wrong"), template, target));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0070")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResponseStatusCodeIsSuccessful2xx()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();

        foreach (int statusCode in new[] { 200, 201, 299 })
        {
            QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture))];

            Http3ConnectUdp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, responseHeaders);
            Assert.True(Http3ConnectUdp.CanProceedAfterHttp3Response(statusCode, requestHeaders, responseHeaders));
        }

        foreach (int statusCode in new[] { 101, 199, 204, 205, 206, 300, 404 })
        {
            QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture))];

            AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(statusCode, requestHeaders, responseHeaders));
            Assert.False(Http3ConnectUdp.CanProceedAfterHttp3Response(statusCode, requestHeaders, responseHeaders));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0071")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResponseMeetsCapsuleProtocolStartRequirements()
    {
        IReadOnlyList<QPackFieldLine> requestHeaders = ValidRequestHeaders();
        QPackFieldLine[] responseHeaders = [new QPackFieldLine(":status", "200")];

        Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, requestHeaders, responseHeaders);
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(204, requestHeaders, [new QPackFieldLine(":status", "204")]));
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(
            200,
            WithoutHeader(requestHeaders, Http3CapsuleProtocol.CapsuleProtocolHeaderName),
            responseHeaders));
        AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(
            200,
            requestHeaders,
            AppendHeader(responseHeaders, new QPackFieldLine("transfer-encoding", "chunked"))));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0072")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidProxyingAttemptFailsAndCannotProceed()
    {
        IReadOnlyList<QPackFieldLine> validRequestHeaders = ValidRequestHeaders();
        QPackFieldLine[] validResponseHeaders = [new QPackFieldLine(":status", "200")];

        Assert.True(Http3ConnectUdp.CanProceedAfterHttp3Response(200, validRequestHeaders, validResponseHeaders));
        foreach (IReadOnlyList<QPackFieldLine> invalidRequestHeaders in new[]
        {
            WithoutHeader(validRequestHeaders, Http3CapsuleProtocol.CapsuleProtocolHeaderName),
            ReplaceHeader(validRequestHeaders, ":method", "GET"),
            ReplaceHeader(validRequestHeaders, ":protocol", "connect-ip"),
            ReplaceHeader(validRequestHeaders, ":path", ""),
        })
        {
            AssertMessageError(() => Http3ConnectUdp.ValidateSuccessfulHttp3Response(200, invalidRequestHeaders, validResponseHeaders));
            Assert.False(Http3ConnectUdp.CanProceedAfterHttp3Response(200, invalidRequestHeaders, validResponseHeaders));
        }
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectUdp.BuildHttp3RequestHeaders(
            Http3ConnectUdpUriTemplate.CreateDefault("proxy.example"),
            new Http3ConnectUdpTarget("example.com", 443));
    }

    private static (Http3ConnectUdpUriTemplate Template, Http3ConnectUdpTarget Target)[] RequestCases()
    {
        return
        [
            (Http3ConnectUdpUriTemplate.CreateDefault("proxy.example"), new Http3ConnectUdpTarget("example.com", 443)),
            (Http3ConnectUdpUriTemplate.Create("https://proxy.example:8443/masque/{target_host}/{target_port}/?token=abc"), new Http3ConnectUdpTarget("192.0.2.1", 53)),
            (Http3ConnectUdpUriTemplate.Create("https://proxy.example/connect/{target_port}/{target_host}"), new Http3ConnectUdpTarget("2001:db8::1", 443)),
        ];
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

    private static QPackFieldLine[] WithoutHeader(IReadOnlyList<QPackFieldLine> headers, string name)
    {
        List<QPackFieldLine> kept = [];
        for (int index = 0; index < headers.Count; index++)
        {
            QPackFieldLine header = headers[index];
            if (!StringComparer.OrdinalIgnoreCase.Equals(header.Name, name))
            {
                kept.Add(header);
            }
        }

        return [.. kept];
    }

    private static QPackFieldLine[] AppendHeader(IReadOnlyList<QPackFieldLine> headers, QPackFieldLine appended)
    {
        QPackFieldLine[] result = new QPackFieldLine[headers.Count + 1];
        for (int index = 0; index < headers.Count; index++)
        {
            result[index] = headers[index];
        }

        result[^1] = appended;
        return result;
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
