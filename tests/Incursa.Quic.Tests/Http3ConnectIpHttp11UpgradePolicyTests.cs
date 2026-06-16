// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpHttp11UpgradePolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0042")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_UsesGetMethod()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ValidRequestHeaders());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0042")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsNonGetMethod()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("POST", ValidRequestHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0043")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_IncludesSingleHostHeader()
    {
        QPackFieldLine host = Assert.Single(Http3ConnectIpHttp11UpgradePolicy.BuildUpgradeRequestHeaders("proxy.example"), header => header.Name == "host");

        Assert.Equal("proxy.example", host.Value);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0043")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsMissingHostHeader()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("host")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0044")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_IncludesConnectionUpgradeHeader()
    {
        Assert.Contains(ValidRequestHeaders(), header => header.Name == "connection" && header.Value == "Upgrade");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0044")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsMissingConnectionUpgradeHeader()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0045")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_IncludesConnectIpUpgradeHeader()
    {
        QPackFieldLine upgrade = Assert.Single(ValidRequestHeaders(), header => header.Name == "upgrade");

        Assert.Equal(Http3ConnectIpFoundationPolicy.ProtocolToken, upgrade.Value);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0045")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsWrongUpgradeHeader()
    {
        IReadOnlyList<QPackFieldLine> headers =
        [
            new QPackFieldLine("host", "proxy.example"),
            new QPackFieldLine("connection", "Upgrade"),
            new QPackFieldLine("upgrade", "connect-udp"),
            Http3CapsuleProtocol.CreateCapsuleProtocolHeader(),
        ];

        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", headers));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0046")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_MalformedRequestProducesValidationError()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RequestHeadersWithout("upgrade")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0046")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_ValidRequestDoesNotProduceValidationError()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ValidRequestHeaders());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0047")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_RecommendsBadRequestForMalformedRequests()
    {
        Assert.Equal(400, Http3ConnectIpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0047")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_DoesNotRecommendSuccessForMalformedRequests()
    {
        Assert.NotEqual(200, Http3ConnectIpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0048")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_ResponseStatusIsSwitchingProtocols()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0048")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsNonSwitchingProtocolsStatus()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(200, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0049")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_ResponseConnectionHeaderIsUpgrade()
    {
        Assert.Contains(ValidResponseHeaders(), header => header.Name == "connection" && header.Value == "Upgrade");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0049")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsResponseWithoutConnectionUpgrade()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ResponseHeadersWithout("connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0050")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_ResponseUpgradeHeaderIsConnectIp()
    {
        QPackFieldLine upgrade = Assert.Single(ValidResponseHeaders(), header => header.Name == "upgrade");

        Assert.Equal(Http3ConnectIpFoundationPolicy.ProtocolToken, upgrade.Value);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0050")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsDuplicateResponseUpgradeHeaders()
    {
        IReadOnlyList<QPackFieldLine> headers =
        [
            new QPackFieldLine("connection", "Upgrade"),
            new QPackFieldLine("upgrade", Http3ConnectIpFoundationPolicy.ProtocolToken),
            new QPackFieldLine("upgrade", Http3ConnectIpFoundationPolicy.ProtocolToken),
        ];

        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, headers));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0051")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_ResponseMeetsCapsuleProtocolStartRequirements()
    {
        Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 0);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0051")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_RejectsResponseContent()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0052")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Http11Upgrade_FailedProxyingAttemptClosesConnection()
    {
        Assert.True(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(200, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0052")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Http11Upgrade_SuccessfulProxyingAttemptDoesNotCloseConnection()
    {
        Assert.False(Http3ConnectIpHttp11UpgradePolicy.ShouldCloseConnectionAfterFailedProxyingAttempt(101, ValidResponseHeaders()));
    }

    private static IReadOnlyList<QPackFieldLine> ValidRequestHeaders()
    {
        return Http3ConnectIpHttp11UpgradePolicy.BuildUpgradeRequestHeaders("proxy.example");
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
}
