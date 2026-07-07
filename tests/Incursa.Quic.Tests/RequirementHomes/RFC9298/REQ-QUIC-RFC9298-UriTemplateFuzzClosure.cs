// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_UriTemplateFuzzClosure
{
    [Fact]
    [Requirement("RFC9298-S2-P5-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateIsLevelThreeOrLower()
    {
        Assert.Equal(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
            Http3ConnectUdpUriTemplate.CreateDefault("proxy.example").Template);

        foreach (string forbidden in new[] { "{.target_host}", "{#target_host}", "{+target_host}", "{;target_host}", "{/target_host}" })
        {
            Assert.Throws<ArgumentException>(() =>
                Http3ConnectUdpUriTemplate.Create($"https://proxy.example/.well-known/masque/udp/{forbidden}/{{target_port}}/"));
        }
    }

    [Fact]
    [Requirement("RFC9298-S2-P4-2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateMustBeAbsoluteForm()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create("/.well-known/masque/udp/{target_host}/{target_port}/"));
        Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create("proxy.example/.well-known/masque/udp/{target_host}/{target_port}/"));

        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");

        Assert.True(template.AbsoluteUri.IsAbsoluteUri);
        Assert.Equal("proxy.example", template.ProxyAuthority);
    }

    [Fact]
    [Requirement("RFC9298-S2-P4-2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRequiresSchemeAuthorityAndPath()
    {
        foreach (string invalidTemplate in new[]
        {
            "https:///.well-known/masque/udp/{target_host}/{target_port}/",
            "https://proxy.example",
            "https://proxy.example?target_host={target_host}&target_port={target_port}",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(invalidTemplate));
        }

        Http3ConnectUdpUriTemplate valid = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        Assert.Equal("https", valid.AbsoluteUri.Scheme);
        Assert.Equal("proxy.example", valid.AbsoluteUri.Authority);
        Assert.StartsWith("/", valid.AbsoluteUri.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplatePathStartsWithSlash()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create("https://proxy.example/masque/{target_host}/{target_port}/");

        Assert.StartsWith("/", template.AbsoluteUri.AbsolutePath, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example?target_host={target_host}&target_port={target_port}"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateVariablesAreOnlyInPathOrQuery()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://{target_host}.example/.well-known/masque/udp/{target_port}/"));

        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/?token=abc");

        Assert.Contains("{target_host}", template.Template, StringComparison.Ordinal);
        Assert.Contains("{target_port}", template.Template, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateMayContainOtherVariables()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/{tenant}");

        Assert.Contains("{tenant}", template.Template, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRequiresTargetHostAndTargetPortVariables()
    {
        foreach (string invalidTemplate in new[]
        {
            "https://proxy.example/.well-known/masque/udp/{target_host}/",
            "https://proxy.example/.well-known/masque/udp/{target_port}/",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(invalidTemplate));
        }

        Assert.Equal(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
            Http3ConnectUdpUriTemplate.CreateDefault("proxy.example").Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRejectsNonAsciiUnicode()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/é"));

        Assert.Equal("https", Http3ConnectUdpUriTemplate.CreateDefault("proxy.example").AbsoluteUri.Scheme);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateAllowsOnlyPrintableAsciiRange()
    {
        foreach (string invalidTemplate in new[]
        {
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/ test",
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/\u007f",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectUdpUriTemplate.Create(invalidTemplate));
        }

        Assert.Equal("https", Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/~ok").AbsoluteUri.Scheme);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsDotPrefixLabelExpansion()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{.target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsFragmentExpansion()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{#target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsReservedExpansion()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{+target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsPathStyleParameterExpansion()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{;target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsPathSegmentExpansion()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{/target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_GeneralPurposeUriTemplateImplementationsRemainUsableWithLocalValidation()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/{extra}");

        Assert.Contains("{extra}", template.Template, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{+target_host}/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientValidatesUriTemplateBeforeUse()
    {
        Assert.NotNull(Http3ConnectUdpUriTemplate.CreateDefault("proxy.example"));
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidUriTemplateConfigurationAbortsBeforeRequest()
    {
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://proxy.example/.well-known/masque/udp/{target_host}/"));
        Assert.Throws<ArgumentException>(() =>
            Http3ConnectUdpUriTemplate.Create("https://{target_host}.example/.well-known/masque/udp/{target_port}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConstrainedClientsMayUseDefaultTemplate()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example:443");

        Assert.Equal("https://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DefaultTemplateLocationIsConcreteForInteroperability()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example");
        Http3ConnectUdpRequestTarget requestTarget = template.Expand(new Http3ConnectUdpTarget("example.com", 443));

        Assert.Equal("/.well-known/masque/udp/{target_host}/{target_port}/", Http3ConnectUdpUriTemplate.DefaultPathTemplate);
        Assert.Equal("/.well-known/masque/udp/example.com/443/", requestTarget.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetHostRejectsIpv6ScopedZoneIdentifiers()
    {
        Assert.Throws<ArgumentException>(() => new Http3ConnectUdpTarget("fe80::1%12", 443));
        Assert.False(Http3ConnectUdpTarget.IsValidTargetHost("fe80::1%12"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetHostAndPortFollowExpectedFormat()
    {
        foreach ((string host, int port) in new[] { ("example.com", 443), ("192.0.2.1", 53), ("2001:db8::1", 65535) })
        {
            Http3ConnectUdpTarget target = new(host, port);

            Assert.Equal(host, target.Host);
            Assert.Equal(port, target.Port);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetHostMustNotBeEmpty()
    {
        Assert.Throws<ArgumentException>(() => new Http3ConnectUdpTarget("", 443));
        Assert.False(Http3ConnectUdpTarget.IsValidTargetHost(""));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetPortMustNotBeEmpty()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectUdpTarget("example.com", 0));
        Assert.Equal(1, new Http3ConnectUdpTarget("example.com", 1).Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Ipv6LiteralColonsArePercentEncodedInTargetHost()
    {
        Http3ConnectUdpTarget target = new("2001:db8::1", 443);
        Http3ConnectUdpRequestTarget requestTarget = Http3ConnectUdpUriTemplate.CreateDefault("proxy.example").Expand(target);

        Assert.Equal("2001%3Adb8%3A%3A1", target.EncodedHost);
        Assert.Contains("2001%3Adb8%3A%3A1", requestTarget.PathAndQuery, StringComparison.Ordinal);
        Assert.DoesNotContain("2001:db8::1", requestTarget.PathAndQuery, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetPortRangeIsOneThrough65535()
    {
        Assert.Equal(1, new Http3ConnectUdpTarget("example.com", 1).Port);
        Assert.Equal(65535, new Http3ConnectUdpTarget("example.com", 65535).Port);
        Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectUdpTarget("example.com", 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectUdpTarget("example.com", 65536));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetHostIsIpv6AddressIpv4AddressOrRegName()
    {
        foreach (string validHost in new[] { "2001:db8::1", "192.0.2.1", "example.com", "host_name.example" })
        {
            Assert.True(Http3ConnectUdpTarget.IsValidTargetHost(validHost));
        }

        Assert.False(Http3ConnectUdpTarget.IsValidTargetHost("bad host"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TargetPortValueIsPort()
    {
        Http3ConnectUdpTarget target = new("example.com", 443);

        Assert.Equal(443, target.Port);
        Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectUdpTarget("example.com", -1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientExpandsTemplateToRequestPathAndQuery()
    {
        Http3ConnectUdpUriTemplate template = Http3ConnectUdpUriTemplate.Create(
            "https://proxy.example:8443/masque/{target_host}/{target_port}/?token=abc");

        Http3ConnectUdpRequestTarget requestTarget = template.Expand(new Http3ConnectUdpTarget("192.0.2.1", 53));

        Assert.Equal("https", requestTarget.Scheme);
        Assert.Equal("proxy.example:8443", requestTarget.Authority);
        Assert.Equal("/masque/192.0.2.1/53/?token=abc", requestTarget.PathAndQuery);
    }
}
