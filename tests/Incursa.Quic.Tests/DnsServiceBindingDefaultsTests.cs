// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class DnsServiceBindingDefaultsTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0033")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SchemeIsDns()
    {
        Assert.Equal("dns", DnsServiceBindingDefaults.Scheme);
        Assert.Equal("_dns", DnsServiceBindingDefaults.NodeName);
    }

    [Theory]
    [InlineData(DnsServiceTransport.CleartextUdp, 53)]
    [InlineData(DnsServiceTransport.CleartextTcp, 53)]
    [InlineData(DnsServiceTransport.DnsOverTls, 853)]
    [InlineData(DnsServiceTransport.DnsOverQuic, 853)]
    [InlineData(DnsServiceTransport.DnsOverHttps, 443)]
    [Requirement("REQ-QUIC-RFC9461-0003")]
    [Requirement("REQ-QUIC-RFC9461-0009")]
    [Requirement("REQ-QUIC-RFC9461-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void GetDefaultPortReturnsPerTransportDefaults(DnsServiceTransport transport, int expectedPort)
    {
        Assert.Equal(expectedPort, DnsServiceBindingDefaults.GetDefaultPort(transport));
    }

    [Theory]
    [InlineData(53, "_dns")]
    [InlineData(443, "_443._dns")]
    [InlineData(853, "_853._dns")]
    [Requirement("REQ-QUIC-RFC9461-0004")]
    [Requirement("REQ-QUIC-RFC9461-0029")]
    [Requirement("REQ-QUIC-RFC9461-0036")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CreateServicePrefixUsesPortPrefixNaming(int port, string expectedPrefix)
    {
        Assert.Equal(expectedPrefix, DnsServiceBindingDefaults.CreateServicePrefix(port));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(65536)]
    [Requirement("REQ-QUIC-RFC9461-0036")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CreateServicePrefixRejectsInvalidPorts(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => DnsServiceBindingDefaults.CreateServicePrefix(port));
    }

    [Theory]
    [InlineData(DnsServiceTransport.CleartextUdp, null, "_dns.resolver.example")]
    [InlineData(DnsServiceTransport.DnsOverQuic, null, "_853._dns.resolver.example")]
    [InlineData(DnsServiceTransport.DnsOverHttps, null, "_443._dns.resolver.example")]
    [InlineData(DnsServiceTransport.DnsOverHttps, 8443, "_8443._dns.resolver.example")]
    [Requirement("REQ-QUIC-RFC9461-0001")]
    [Requirement("REQ-QUIC-RFC9461-0004")]
    [Requirement("REQ-QUIC-RFC9461-0009")]
    [Requirement("REQ-QUIC-RFC9461-0036")]
    [Requirement("REQ-QUIC-RFC9461-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CreateServiceNameCombinesPortPrefixAndAuthenticationHostname(
        DnsServiceTransport transport,
        int? port,
        string expectedServiceName)
    {
        string serviceName = DnsServiceBindingDefaults.CreateServiceName("Resolver.Example", transport, port);

        Assert.Equal(expectedServiceName, serviceName);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CreateServiceNamePreservesAbsoluteHostnameForm()
    {
        string serviceName = DnsServiceBindingDefaults.CreateServiceName(
            "resolver.example.",
            DnsServiceTransport.DnsOverQuic);

        Assert.Equal("_853._dns.resolver.example.", serviceName);
    }

    [Theory]
    [InlineData("resolver.example")]
    [InlineData("192.0.2.1")]
    [InlineData("2001:db8::1")]
    [InlineData("[2001:db8::1]")]
    [Requirement("REQ-QUIC-RFC9461-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AuthenticationNameAcceptsDnsHostnamesAndLiteralIpAddresses(string authenticationName)
    {
        Assert.True(DnsServiceBindingDefaults.IsValidAuthenticationName(authenticationName));
    }

    [Theory]
    [InlineData("")]
    [InlineData("_resolver.example")]
    [InlineData("-resolver.example")]
    [InlineData("resolver..example")]
    [Requirement("REQ-QUIC-RFC9461-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AuthenticationNameRejectsInvalidNames(string authenticationName)
    {
        Assert.False(DnsServiceBindingDefaults.IsValidAuthenticationName(authenticationName));
    }
}
