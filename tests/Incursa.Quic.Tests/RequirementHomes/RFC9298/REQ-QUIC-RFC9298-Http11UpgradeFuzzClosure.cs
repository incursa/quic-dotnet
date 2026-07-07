// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_Http11UpgradeFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0053")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeRequestMethodIsGet()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ValidRequestHeaders());

        Assert.Equal("GET", Http3ConnectUdpHttp11UpgradePolicy.RequestMethod);
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("POST", ValidRequestHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0054")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeRequestHasSingleHostHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Single(headers, header => header.Name == "host" && header.Value == "proxy.example");
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RemoveHeader(headers, "host")));
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", [.. headers, new QPackFieldLine("host", "other.example")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0055")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeRequestHasConnectionUpgradeToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == "connection" && header.Value == "Upgrade");
        Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ReplaceHeader(headers, "connection", "keep-alive, upgrade"));
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RemoveHeader(headers, "connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0056")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeRequestHasConnectUdpUpgradeHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Single(headers, header => header.Name == "upgrade" && header.Value == Http3ConnectUdp.ProtocolToken);
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RemoveHeader(headers, "upgrade")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0057")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedUpgradeRequestProducesError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() =>
            Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("POST", ValidRequestHeaders()));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0058")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedUpgradeRequestUsesBadRequestRecommendation()
    {
        Assert.Equal(400, Http3ConnectUdpHttp11UpgradePolicy.MalformedRequestStatusCode);
        Assert.NotEqual(101, Http3ConnectUdpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0059")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeResponseStatusIsSwitchingProtocols()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders());

        Assert.Equal(101, Http3ConnectUdpHttp11UpgradePolicy.SwitchingProtocolsStatusCode);
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(200, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("RFC9298-S3-3-P2-2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeResponseHasConnectionUpgradeToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidResponseHeaders();

        Assert.Contains(headers, header => header.Name == "connection" && header.Value == "Upgrade");
        Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ReplaceHeader(headers, "connection", "keep-alive, upgrade"));
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, RemoveHeader(headers, "connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0061")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeResponseHasSingleConnectUdpUpgradeHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidResponseHeaders();

        Assert.Single(headers, header => header.Name == "upgrade" && header.Value == Http3ConnectUdp.ProtocolToken);
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. headers, new QPackFieldLine("upgrade", Http3ConnectUdp.ProtocolToken)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0062")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UpgradeResponseStartsCapsuleProtocolWithoutContent()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 0);

        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(101, ValidResponseHeaders()));
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. ValidResponseHeaders(), new QPackFieldLine("content-length", "1")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0063")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientAbortsProxyingAttemptWhenUpgradeRequirementsFail()
    {
        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(101, ValidResponseHeaders()));
        Assert.False(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(200, ValidResponseHeaders()));
        Assert.False(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(101, RemoveHeader(ValidResponseHeaders(), "upgrade")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0064")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerSendsRequiredExtendedConnectHttpSetting()
    {
        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.ServerMustSendHttpSetting);
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectUdpHttp11UpgradePolicy.BuildUpgradeRequestHeaders("proxy.example");
    }

    private static IReadOnlyList<QPackFieldLine> ValidResponseHeaders()
    {
        return Http3ConnectUdpHttp11UpgradePolicy.BuildSwitchingProtocolsResponseHeaders();
    }

    private static QPackFieldLine[] RemoveHeader(IReadOnlyList<QPackFieldLine> headers, string name)
    {
        return headers.Where(header => header.Name != name).ToArray();
    }

    private static QPackFieldLine[] ReplaceHeader(IReadOnlyList<QPackFieldLine> headers, string name, string value)
    {
        return headers.Select(header => header.Name == name ? new QPackFieldLine(header.Name, value) : header).ToArray();
    }
}
