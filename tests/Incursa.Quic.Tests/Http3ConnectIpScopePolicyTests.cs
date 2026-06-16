// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpScopePolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0065")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TargetScope_AcceptsIpPrefixWithSingleIpVersion()
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24", out Http3ConnectIpTargetScope scope));

        Assert.True(Http3ConnectIpScopePolicy.PrefixTargetUsesSingleIpVersion(scope));
        Assert.Equal(Http3ConnectIpScopePolicy.Ipv4Version, Http3ConnectIpScopePolicy.GetIpVersion(scope.Address!));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0065")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TargetScope_RejectsMixedOrMalformedPrefixScope()
    {
        Assert.False(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24/2001:db8::/64", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0066")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_IncludesAccessibleResolvedAddressWithAssignedFamily()
    {
        bool advertise = Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(
            IPAddress.Parse("192.0.2.20"),
            accessibleToProxy: true,
            assignedAddressFamilies: [Http3ConnectIpScopePolicy.Ipv4Version]);

        Assert.True(advertise);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0066")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, 4)]
    [InlineData(true, 6)]
    public void RouteAdvertisement_ExcludesInaccessibleOrUnassignedFamilyAddress(bool accessibleToProxy, int assignedFamily)
    {
        bool advertise = Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(
            IPAddress.Parse("192.0.2.20"),
            accessibleToProxy,
            assignedAddressFamilies: [assignedFamily]);

        Assert.False(advertise);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0067")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtocolScope_SpecificIpprotoAllowsOnlySelectedProtocolAndIcmp()
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out Http3ConnectIpProtocolScope scope));

        Assert.True(scope.AllowsProtocol(17));
        Assert.Equal(17, scope.ProtocolNumber);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0067")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolScope_SpecificIpprotoRejectsDifferentNonIcmpProtocol()
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out Http3ConnectIpProtocolScope scope));

        Assert.False(scope.AllowsProtocol(6));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0068")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(null)]
    [InlineData("*")]
    public void ProtocolScope_WildcardOrOmittedIpprotoAllowsAnyProtocol(string? ipproto)
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out Http3ConnectIpProtocolScope scope));

        Assert.True(scope.AllowsAnyProtocol);
        Assert.True(scope.AllowsProtocol(132));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0068")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolScope_SpecificIpprotoDoesNotMeanAnyProtocol()
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out Http3ConnectIpProtocolScope scope));

        Assert.False(scope.AllowsAnyProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0069")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtocolScope_AllowsValidOutermostNextHeaderValue()
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("132", out Http3ConnectIpProtocolScope scope));

        Assert.True(scope.AllowsProtocol(132));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0069")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolScope_RejectsOutOfRangeNextHeaderValue()
    {
        Assert.False(Http3ConnectIpProtocolScope.TryParse("256", out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0070")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber)]
    [InlineData(Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber)]
    public void ProtocolScope_AlwaysAllowsIcmpTraffic(int icmpProtocol)
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out Http3ConnectIpProtocolScope scope));

        Assert.True(scope.AllowsProtocol(icmpProtocol));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0070")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolScope_IcmpExceptionDoesNotAllowEveryOtherProtocol()
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out Http3ConnectIpProtocolScope scope));

        Assert.False(scope.AllowsProtocol(6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0071")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ScopeGrammar_AcceptsFigure6TargetAndIpprotoValues()
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse("2001:db8::/64", out _));
        Assert.True(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24", out _));
        Assert.True(Http3ConnectIpTargetScope.TryParse("host.example", out _));
        Assert.True(Http3ConnectIpTargetScope.TryParse("*", out _));
        Assert.True(Http3ConnectIpProtocolScope.TryParse("17", out _));
        Assert.True(Http3ConnectIpProtocolScope.TryParse("*", out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0071")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("host example", "17")]
    [InlineData("192.0.2.1/24", "17")]
    [InlineData("host.example", "udp")]
    public void ScopeGrammar_RejectsValuesOutsideFigure6Format(string target, string ipproto)
    {
        Assert.False(Http3ConnectIpTargetScope.TryParse(target, out _) && Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0072")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplateExpansion_PercentEncodesColonsInIpv6Targets()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::1",
            "58");

        Assert.Contains(headers, header => header.Name == ":path" && header.Value.Contains("2001%3Adb8%3A%3A1", StringComparison.Ordinal));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0072")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplateExpansion_DoesNotEmitRawColonsInIpv6TargetSegment()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::1",
            "58");

        Assert.DoesNotContain("2001:db8::1", GetPath(headers), StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0073")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplateExpansion_PercentEncodesPrefixSlash()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::/64",
            "58");

        Assert.Contains("2001%3Adb8%3A%3A%2F64", GetPath(headers), StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0073")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplateExpansion_DoesNotEmitRawPrefixSlashInsideTargetSegment()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::/64",
            "58");

        Assert.DoesNotContain("2001:db8::/64", GetPath(headers), StringComparison.Ordinal);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0074")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("0.0.0.0/0")]
    [InlineData("192.0.2.0/24")]
    [InlineData("2001:db8::/128")]
    public void TargetScope_AcceptsPrefixLengthWithinAddressBitLength(string target)
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse(target, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0074")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("192.0.2.0/33")]
    [InlineData("2001:db8::/129")]
    public void TargetScope_RejectsPrefixLengthOutsideAddressBitLength(string target)
    {
        Assert.False(Http3ConnectIpTargetScope.TryParse(target, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0075")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TargetScope_AcceptsPrefixWithZeroUncoveredLowerBits()
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0075")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TargetScope_RejectsPrefixWithNonZeroUncoveredLowerBits()
    {
        Assert.False(Http3ConnectIpTargetScope.TryParse("192.0.2.1/24", out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0076")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("0")]
    [InlineData("255")]
    [InlineData("*")]
    public void ProtocolScope_AcceptsDecimalZeroTo255OrWildcard(string ipproto)
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0076")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("-1")]
    [InlineData("256")]
    public void ProtocolScope_RejectsValuesOutsideDecimalZeroTo255(string ipproto)
    {
        Assert.False(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0077")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("1")]
    [InlineData("17")]
    [InlineData("255")]
    [InlineData("*")]
    public void ProtocolScope_AcceptsIpprotoGrammarAlternatives(string ipproto)
    {
        Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0077")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("1234")]
    [InlineData("udp")]
    public void ProtocolScope_RejectsInvalidIpprotoGrammarAlternatives(string ipproto)
    {
        Assert.False(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0078")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("2001:db8::/64")]
    [InlineData("192.0.2.0/24")]
    [InlineData("host.example")]
    [InlineData("*")]
    public void TargetScope_AcceptsTargetGrammarAlternatives(string target)
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse(target, out _));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0078")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("host example")]
    [InlineData("host.example/24")]
    public void TargetScope_RejectsInvalidTargetGrammarAlternatives(string target)
    {
        Assert.False(Http3ConnectIpTargetScope.TryParse(target, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0079")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AccessControl_CanRejectUnauthorizedClientScope()
    {
        Assert.True(Http3ConnectIpScopePolicy.ShouldRejectForAccessControl(
            accessControlEnabled: true,
            clientAuthorizedForAnyDestinationInScope: false));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0079")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void AccessControl_DoesNotRejectWhenDisabledOrAuthorized(bool accessControlEnabled, bool clientAuthorized)
    {
        Assert.False(Http3ConnectIpScopePolicy.ShouldRejectForAccessControl(accessControlEnabled, clientAuthorized));
    }

    private static string GetPath(IReadOnlyList<QPackFieldLine> headers)
    {
        return headers.Single(header => header.Name == ":path").Value;
    }
}
