// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_ScopePolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0065")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetIpPrefixUsesOnlyOneIpVersion()
    {
        foreach ((string target, int expectedVersion) in new[] { ("192.0.2.0/24", 4), ("2001:db8::/64", 6) })
        {
            Assert.True(Http3ConnectIpTargetScope.TryParse(target, out Http3ConnectIpTargetScope scope));
            Assert.True(Http3ConnectIpScopePolicy.PrefixTargetUsesSingleIpVersion(scope));
            Assert.Equal(expectedVersion, Http3ConnectIpScopePolicy.GetIpVersion(scope.Address!));
        }

        Assert.False(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24/2001:db8::/64", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0066")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementIncludesAccessibleResolvedAddressWithAssignedFamily()
    {
        Assert.True(Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(IPAddress.Parse("192.0.2.20"), accessibleToProxy: true, assignedAddressFamilies: [4]));
        Assert.True(Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(IPAddress.Parse("2001:db8::20"), accessibleToProxy: true, assignedAddressFamilies: [6]));
        Assert.False(Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(IPAddress.Parse("192.0.2.20"), accessibleToProxy: false, assignedAddressFamilies: [4]));
        Assert.False(Http3ConnectIpScopePolicy.ShouldAdvertiseResolvedRoute(IPAddress.Parse("192.0.2.20"), accessibleToProxy: true, assignedAddressFamilies: [6]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0067")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PresentIpprotoSpecifiesSpecificProtocol()
    {
        foreach (string ipproto in new[] { "1", "6", "17", "132", "255" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out Http3ConnectIpProtocolScope scope));
            Assert.False(scope.AllowsAnyProtocol);
            Assert.True(scope.AllowsProtocol(scope.ProtocolNumber!.Value));
        }

        Assert.False(Http3ConnectIpProtocolScope.TryParse("udp", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0068")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_WildcardOrOmittedIpprotoRequestsAnyProtocol()
    {
        foreach (string? ipproto in new[] { null, "", "*" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out Http3ConnectIpProtocolScope scope));
            Assert.True(scope.AllowsAnyProtocol);
            Assert.True(scope.AllowsProtocol(6));
            Assert.True(scope.AllowsProtocol(132));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0069")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpprotoIndicatesAllowableOutermostNextHeaderValue()
    {
        foreach (string ipproto in new[] { "0", "1", "6", "17", "58", "132", "255" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out Http3ConnectIpProtocolScope scope));
            Assert.True(scope.AllowsProtocol(scope.ProtocolNumber!.Value));
        }

        Assert.False(Http3ConnectIpProtocolScope.TryParse("256", out _));
        Assert.False(Http3ConnectIpProtocolScope.TryParse("-1", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0070")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IcmpTrafficIsAlwaysAllowedRegardlessOfIpproto()
    {
        foreach (string ipproto in new[] { "6", "17", "132" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out Http3ConnectIpProtocolScope scope));
            Assert.True(scope.AllowsProtocol(Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber));
            Assert.True(scope.AllowsProtocol(Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0071")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetAndIpprotoConformToFigureSixFormat()
    {
        foreach (string target in new[] { "2001:db8::/64", "192.0.2.0/24", "host.example", "*" })
        {
            Assert.True(Http3ConnectIpTargetScope.TryParse(target, out _));
        }

        foreach (string ipproto in new[] { "17", "255", "*" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
        }

        Assert.False(Http3ConnectIpTargetScope.TryParse("host example", out _));
        Assert.False(Http3ConnectIpProtocolScope.TryParse("udp", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0072")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6TargetColonsArePercentEncoded()
    {
        string path = GetPath(Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::1",
            "58"));

        Assert.Contains("2001%3Adb8%3A%3A1", path, StringComparison.Ordinal);
        Assert.DoesNotContain("2001:db8::1", path, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0073")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetPrefixSlashIsPercentEncoded()
    {
        string path = GetPath(Http3ConnectIp.BuildHttp3RequestHeaders(
            Http3ConnectIpUriTemplate.CreateDefault("proxy.example"),
            "2001:db8::/64",
            "58"));

        Assert.Contains("2001%3Adb8%3A%3A%2F64", path, StringComparison.Ordinal);
        Assert.DoesNotContain("2001:db8::/64", path, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0074")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPrefixLengthFitsAddressBitLength()
    {
        foreach (string target in new[] { "0.0.0.0/0", "192.0.2.0/24", "192.0.2.1/32", "2001:db8::/64", "2001:db8::1/128" })
        {
            Assert.True(Http3ConnectIpTargetScope.TryParse(target, out _));
        }

        Assert.False(Http3ConnectIpTargetScope.TryParse("192.0.2.0/33", out _));
        Assert.False(Http3ConnectIpTargetScope.TryParse("2001:db8::/129", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0075")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPrefixLowerBitsOutsidePrefixAreZero()
    {
        Assert.True(Http3ConnectIpTargetScope.TryParse("192.0.2.0/24", out _));
        Assert.True(Http3ConnectIpTargetScope.TryParse("2001:db8::/64", out _));
        Assert.False(Http3ConnectIpTargetScope.TryParse("192.0.2.1/24", out _));
        Assert.False(Http3ConnectIpTargetScope.TryParse("2001:db8::1/64", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0076")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpprotoIsDecimalZeroTo255OrWildcard()
    {
        foreach (string ipproto in new[] { "0", "1", "17", "255", "*" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
        }

        foreach (string ipproto in new[] { "-1", "256", "udp" })
        {
            Assert.False(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0077")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpprotoGrammarIsOneToThreeDigitsOrWildcard()
    {
        foreach (string ipproto in new[] { "1", "17", "255", "*" })
        {
            Assert.True(Http3ConnectIpProtocolScope.TryParse(ipproto, out _));
        }

        Assert.False(Http3ConnectIpProtocolScope.TryParse("1234", out _));
        Assert.False(Http3ConnectIpProtocolScope.TryParse("tcp", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0078")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetGrammarAcceptsIpPrefixesRegNameOrWildcard()
    {
        foreach (string target in new[] { "2001:db8::/64", "192.0.2.0/24", "host.example", "service_1.example", "*" })
        {
            Assert.True(Http3ConnectIpTargetScope.TryParse(target, out _));
        }

        Assert.False(Http3ConnectIpTargetScope.TryParse("host example", out _));
        Assert.False(Http3ConnectIpTargetScope.TryParse("host.example/24", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0079")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AccessControlCanRejectUnauthorizedClientScope()
    {
        Assert.True(Http3ConnectIpScopePolicy.ShouldRejectForAccessControl(accessControlEnabled: true, clientAuthorizedForAnyDestinationInScope: false));
        Assert.False(Http3ConnectIpScopePolicy.ShouldRejectForAccessControl(accessControlEnabled: false, clientAuthorizedForAnyDestinationInScope: false));
        Assert.False(Http3ConnectIpScopePolicy.ShouldRejectForAccessControl(accessControlEnabled: true, clientAuthorizedForAnyDestinationInScope: true));
    }

    private static string GetPath(IReadOnlyList<QPackFieldLine> headers)
    {
        return headers.Single(header => header.Name == ":path").Value;
    }
}
