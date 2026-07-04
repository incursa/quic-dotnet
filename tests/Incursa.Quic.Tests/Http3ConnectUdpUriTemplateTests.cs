// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpUriTemplateTests
{
    [Fact]
    [Requirement("RFC9298-S2-P5-S1-R01")]
    [Requirement("RFC9298-S2-P4-2-R01")]
    [Requirement("RFC9298-S2-P4-2-R02")]
    [Requirement("REQ-QUIC-RFC9298-0005")]
    [Requirement("REQ-QUIC-RFC9298-0006")]
    [Requirement("REQ-QUIC-RFC9298-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsAbsolutePrintableLevelThreeTemplateWithRequiredVariables()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/");

        Assert.Equal("https", template.AbsoluteUri.Scheme);
        Assert.Equal("proxy.example", template.ProxyAuthority);
        Assert.StartsWith("/", template.AbsoluteUri.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0009")]
    [Requirement("REQ-QUIC-RFC9298-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsPrintableAsciiTemplates()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/?token=abc");

        Assert.Equal("https", template.AbsoluteUri.Scheme);
    }

    [Theory]
    [Requirement("RFC9298-S2-P5-S1-R01")]
    [Requirement("REQ-QUIC-RFC9298-0011")]
    [Requirement("REQ-QUIC-RFC9298-0012")]
    [Requirement("REQ-QUIC-RFC9298-0013")]
    [Requirement("REQ-QUIC-RFC9298-0014")]
    [Requirement("REQ-QUIC-RFC9298-0015")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("https://proxy.example/.well-known/{.target_host}/{target_port}/")]
    [InlineData("https://proxy.example/.well-known/{#target_host}/{target_port}/")]
    [InlineData("https://proxy.example/.well-known/{+target_host}/{target_port}/")]
    [InlineData("https://proxy.example/.well-known/{;target_host}/{target_port}/")]
    [InlineData("https://proxy.example/.well-known/{/target_host}/{target_port}/")]
    public void UriTemplate_RejectsForbiddenLevelFourExpansionOperators(string value)
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0011")]
    [Requirement("REQ-QUIC-RFC9298-0012")]
    [Requirement("REQ-QUIC-RFC9298-0013")]
    [Requirement("REQ-QUIC-RFC9298-0014")]
    [Requirement("REQ-QUIC-RFC9298-0015")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsTemplatesWithoutForbiddenExpansionOperators()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/");

        Assert.DoesNotContain("{+", template.Template, StringComparison.Ordinal);
    }

    [Theory]
    [Requirement("RFC9298-S2-P4-2-R01")]
    [Requirement("RFC9298-S2-P4-2-R02")]
    [Requirement("REQ-QUIC-RFC9298-0005")]
    [Requirement("REQ-QUIC-RFC9298-0006")]
    [Requirement("REQ-QUIC-RFC9298-0008")]
    [Requirement("REQ-QUIC-RFC9298-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("/.well-known/masque/udp/{target_host}/{target_port}/")]
    [InlineData("https:///.well-known/masque/udp/{target_host}/{target_port}/")]
    [InlineData("https://proxy.example")]
    [InlineData("https://{target_host}.example/.well-known/masque/udp/{target_port}/")]
    [InlineData("https://proxy.example/.well-known/masque/udp/{target_host}/")]
    public void UriTemplate_RejectsInvalidConfigurationBeforeSendingRequest(string value)
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_InvalidConfigurationIsRejectedBeforeRequestIsSent()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/"));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0009")]
    [Requirement("REQ-QUIC-RFC9298-0010")]
    [Requirement("REQ-QUIC-RFC9298-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/é")]
    [InlineData("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/ test")]
    public void UriTemplate_RejectsNonPrintableOrNonAsciiCharacters(string value)
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(value));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0007")]
    [Requirement("REQ-QUIC-RFC9298-0016")]
    [Requirement("REQ-QUIC-RFC9298-0017")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AllowsOtherSimpleVariablesForGeneralPurposeExpansion()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/{extra}");

        Assert.Contains("{extra}", template.Template, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0019")]
    [Requirement("REQ-QUIC-RFC9298-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_CreatesDefaultTemplateForConstrainedClients()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");

        Assert.Equal("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0024")]
    [Requirement("REQ-QUIC-RFC9298-0025")]
    [Requirement("REQ-QUIC-RFC9298-0026")]
    [Requirement("REQ-QUIC-RFC9298-0027")]
    [Requirement("REQ-QUIC-RFC9298-0029")]
    [Requirement("REQ-QUIC-RFC9298-0031")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Target_AcceptsNonEmptyHostAndValidPort()
    {
        Http3ConnectUdpTarget target = new("example.com", 443);

        Assert.Equal("example.com", target.Host);
        Assert.Equal(443, target.Port);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0024")]
    [Requirement("REQ-QUIC-RFC9298-0025")]
    [Requirement("REQ-QUIC-RFC9298-0026")]
    [Requirement("REQ-QUIC-RFC9298-0030")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("")]
    [InlineData("fe80::1%12")]
    [InlineData("bad host")]
    public void Target_RejectsEmptyScopedOrInvalidHosts(string host)
    {
        Assert.Throws<ArgumentException>(() => new Http3ConnectUdpTarget(host, 443));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0027")]
    [Requirement("REQ-QUIC-RFC9298-0029")]
    [Requirement("REQ-QUIC-RFC9298-0031")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(0)]
    [InlineData(65536)]
    public void Target_RejectsInvalidPorts(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectUdpTarget("example.com", port));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0028")]
    [Requirement("REQ-QUIC-RFC9298-0030")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Target_PercentEncodesIpv6LiteralColons()
    {
        Http3ConnectUdpTarget target = new("2001:db8::1", 443);

        Assert.Equal("2001%3Adb8%3A%3A1", target.EncodedHost);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0028")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_ExpansionDoesNotLeaveRawIpv6ColonsInTargetHost()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");

        Http3ConnectUdpRequestTarget requestTarget = template.Expand(new Http3ConnectUdpTarget("2001:db8::1", 443));

        Assert.DoesNotContain("2001:db8::1", requestTarget.PathAndQuery, StringComparison.Ordinal);
        Assert.Contains("2001%3Adb8%3A%3A1", requestTarget.PathAndQuery, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_ExpandsRequestPathAndQuery()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example:8443/masque/{target_host}/{target_port}/?token=abc");

        Http3ConnectUdpRequestTarget requestTarget = template.Expand(new Http3ConnectUdpTarget("192.0.2.1", 53));

        Assert.Equal("https", requestTarget.Scheme);
        Assert.Equal("proxy.example:8443", requestTarget.Authority);
        Assert.Equal("/masque/192.0.2.1/53/?token=abc", requestTarget.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DoesNotExpandInvalidTargets()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");

        Assert.Throws<ArgumentException>(() => template.Expand(new Http3ConnectUdpTarget("bad host", 53)));
    }
}
