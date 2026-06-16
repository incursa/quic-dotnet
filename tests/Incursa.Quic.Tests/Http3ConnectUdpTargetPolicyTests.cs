// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpTargetPolicyTests
{
    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0116")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("169.254.10.20")]
    [InlineData("fe80::1")]
    [InlineData("224.0.0.1")]
    [InlineData("ff02::1")]
    [InlineData("255.255.255.255")]
    public void TargetPolicy_DisallowsVulnerableTargets(string address)
    {
        Assert.True(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(IPAddress.Parse(address)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0116")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TargetPolicy_DisallowsProxyOwnAddresses()
    {
        IPAddress proxyAddress = IPAddress.Parse("192.0.2.10");

        Assert.True(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(proxyAddress, [proxyAddress]));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0116")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("192.0.2.55")]
    [InlineData("2001:db8::55")]
    public void TargetPolicy_AllowsNonVulnerableDocumentationTargets(string address)
    {
        Assert.False(Http3ConnectUdpTargetPolicy.IsVulnerableTarget(IPAddress.Parse(address), [IPAddress.Parse("192.0.2.10")]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0117")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TargetPolicy_CreatesDestinationIpProhibitedProxyStatusHeader()
    {
        QPackFieldLine header = Http3ConnectUdpTargetPolicy.CreateDestinationIpProhibitedProxyStatusHeader();

        Assert.Equal("proxy-status", header.Name);
        Assert.Contains(Http3ConnectUdpTargetPolicy.DestinationIpProhibitedErrorType, header.Value, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0117")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TargetPolicy_DestinationIpProhibitedHeaderDoesNotUseUnrelatedErrorType()
    {
        QPackFieldLine header = Http3ConnectUdpTargetPolicy.CreateDestinationIpProhibitedProxyStatusHeader();

        Assert.DoesNotContain("connection_timeout", header.Value, StringComparison.Ordinal);
    }
}
