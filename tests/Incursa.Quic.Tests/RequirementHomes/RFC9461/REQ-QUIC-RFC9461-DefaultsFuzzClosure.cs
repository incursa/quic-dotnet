// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9461_DefaultsFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0001_ServiceNamesUseDnsPortPrefixNaming()
    {
        Assert.Equal("_dns.resolver.example", DnsServiceBindingDefaults.CreateServiceName("Resolver.Example", DnsServiceTransport.CleartextUdp));
        Assert.Equal("_853._dns.resolver.example", DnsServiceBindingDefaults.CreateServiceName("Resolver.Example", DnsServiceTransport.DnsOverQuic));
        Assert.Equal("_443._dns.resolver.example", DnsServiceBindingDefaults.CreateServiceName("Resolver.Example", DnsServiceTransport.DnsOverHttps));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0002_AuthenticationNameIsDnsHostnameOrLiteralIpAddress()
    {
        Assert.True(DnsServiceBindingDefaults.IsValidAuthenticationName("resolver.example"));
        Assert.True(DnsServiceBindingDefaults.IsValidAuthenticationName("192.0.2.53"));
        Assert.True(DnsServiceBindingDefaults.IsValidAuthenticationName("[2001:db8::53]"));

        Assert.False(DnsServiceBindingDefaults.IsValidAuthenticationName("_resolver.example"));
        Assert.False(DnsServiceBindingDefaults.IsValidAuthenticationName("resolver..example"));
        Assert.False(DnsServiceBindingDefaults.IsValidAuthenticationName("-resolver.example"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0003_CleartextDnsUsesPortFiftyThree()
    {
        Assert.Equal(53, DnsServiceBindingDefaults.GetDefaultPort(DnsServiceTransport.CleartextUdp));
        Assert.Equal(53, DnsServiceBindingDefaults.GetDefaultPort(DnsServiceTransport.CleartextTcp));
        Assert.NotEqual(53, DnsServiceBindingDefaults.GetDefaultPort(DnsServiceTransport.DnsOverQuic));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0004_NonDefaultPortsArePlacedInAdditionalPrefix()
    {
        Assert.Equal("_dns", DnsServiceBindingDefaults.CreateServicePrefix(53));
        Assert.Equal("_443._dns", DnsServiceBindingDefaults.CreateServicePrefix(443));
        Assert.Equal("_8853._dns", DnsServiceBindingDefaults.CreateServicePrefix(8853));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0029_DnsNodeNameIsRegisteredForSvcb()
    {
        Assert.Equal("_dns", DnsServiceBindingDefaults.NodeName);
        Assert.Equal("_dns", DnsServiceBindingDefaults.CreateServicePrefix(DnsServiceBindingDefaults.CleartextDnsDefaultPort));
        Assert.StartsWith("_853._dns", DnsServiceBindingDefaults.CreateServiceName("resolver.example", DnsServiceTransport.DnsOverQuic), StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0033_MappedSchemeIsDns()
    {
        Assert.Equal("dns", DnsServiceBindingDefaults.Scheme);
        Assert.NotEqual("doq", DnsServiceBindingDefaults.Scheme);
        Assert.NotEqual("https", DnsServiceBindingDefaults.Scheme);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0036")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0036_NamePrefixUsesDnsForPortFiftyThreeAndPortDnsOtherwise()
    {
        Assert.Equal("_dns", DnsServiceBindingDefaults.CreateServicePrefix(53));
        Assert.Equal("_853._dns", DnsServiceBindingDefaults.CreateServicePrefix(853));
        Assert.Equal("_8443._dns", DnsServiceBindingDefaults.CreateServicePrefix(8443));
    }
}
