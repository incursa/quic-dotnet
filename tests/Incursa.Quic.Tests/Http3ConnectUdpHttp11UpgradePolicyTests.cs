// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpHttp11UpgradePolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0053")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeRequest_UsesGetMethod()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", ValidRequestHeaders());

        Assert.Equal("GET", Http3ConnectUdpHttp11UpgradePolicy.RequestMethod);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0053")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeRequest_RejectsNonGetMethod()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("POST", ValidRequestHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0054")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeRequest_IncludesSingleHostHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Single(headers, header => header.Name == "host" && header.Value == "proxy.example");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0054")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeRequest_RejectsMissingOrDuplicateHostHeaders()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", [.. ValidRequestHeaders(), new QPackFieldLine("host", "other.example")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0055")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeRequest_IncludesConnectionUpgradeToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == "connection" && header.Value == "Upgrade");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0055")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeRequest_RejectsMissingConnectionUpgradeToken()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RemoveHeader(ValidRequestHeaders(), "connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0056")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeRequest_IncludesConnectUdpUpgradeHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidRequestHeaders();

        Assert.Contains(headers, header => header.Name == "upgrade" && header.Value == Http3ConnectUdp.ProtocolToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0056")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeRequest_RejectsMissingConnectUdpUpgradeHeader()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateUpgradeRequest("GET", RemoveHeader(ValidRequestHeaders(), "upgrade")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0057")]
    [Requirement("REQ-QUIC-RFC9298-0058")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeRequest_MalformedRequestsUseBadRequestRecommendation()
    {
        Assert.Equal(400, Http3ConnectUdpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0057")]
    [Requirement("REQ-QUIC-RFC9298-0058")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeRequest_MalformedRequestsDoNotUseSuccessfulStatus()
    {
        Assert.NotEqual(200, Http3ConnectUdpHttp11UpgradePolicy.MalformedRequestStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0059")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeResponse_UsesSwitchingProtocolsStatus()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders());

        Assert.Equal(101, Http3ConnectUdpHttp11UpgradePolicy.SwitchingProtocolsStatusCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0059")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeResponse_RejectsNonSwitchingProtocolsStatus()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(200, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("RFC9298-S3-3-P2-2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeResponse_IncludesConnectionUpgradeToken()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidResponseHeaders();

        Assert.Contains(headers, header => header.Name == "connection" && header.Value == "Upgrade");
    }

    [Fact]
    [Requirement("RFC9298-S3-3-P2-2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeResponse_RejectsMissingConnectionUpgradeToken()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, RemoveHeader(ValidResponseHeaders(), "connection")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0061")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeResponse_IncludesSingleConnectUdpUpgradeHeader()
    {
        IReadOnlyList<QPackFieldLine> headers = ValidResponseHeaders();

        Assert.Single(headers, header => header.Name == "upgrade" && header.Value == Http3ConnectUdp.ProtocolToken);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0061")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeResponse_RejectsDuplicateConnectUdpUpgradeHeaders()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. ValidResponseHeaders(), new QPackFieldLine("upgrade", Http3ConnectUdp.ProtocolToken)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0062")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeResponse_MeetsCapsuleNoContentRequirements()
    {
        Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, ValidResponseHeaders(), contentLength: 0);

        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(101, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0062")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeResponse_RejectsMessageContent()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectUdpHttp11UpgradePolicy.ValidateSwitchingProtocolsResponse(101, [.. ValidResponseHeaders(), new QPackFieldLine("content-length", "1")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0063")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradeResponse_AllowsProceedWhenRequirementsAreMet()
    {
        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(101, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0063")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradeResponse_FailsProxyingAttemptWhenRequirementsAreMissing()
    {
        Assert.False(Http3ConnectUdpHttp11UpgradePolicy.CanProceedAfterUpgradeResponse(200, ValidResponseHeaders()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0064")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UpgradePolicy_RequiresServerHttpSetting()
    {
        Assert.True(Http3ConnectUdpHttp11UpgradePolicy.ServerMustSendHttpSetting);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0064")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UpgradePolicy_DoesNotAllowOmittingServerHttpSetting()
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
}
