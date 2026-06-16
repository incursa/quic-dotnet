// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpUriTemplateTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsLevelThreeTemplate()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}{?ipproto}");

        Assert.Equal("https://proxy.example/ip/{target}{?ipproto}", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsForbiddenLevelFourOperators()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{+target}/{ipproto}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsAbsoluteTemplate()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{ipproto}/");

        Assert.Equal("proxy.example", template.ProxyAuthority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsRelativeTemplate()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("/ip/{target}/{ipproto}/"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsTemplateWithNonEmptyComponents()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{ipproto}/");

        Assert.Equal("https", template.AbsoluteUri.Scheme);
        Assert.Equal("proxy.example", template.AbsoluteUri.Authority);
        Assert.Equal("/ip/x/x/", template.AbsoluteUri.AbsolutePath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsTemplateWithMissingPathComponent()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("https://proxy.example"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsSlashPrefixedPath()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault("proxy.example");

        Assert.StartsWith("/", template.AbsoluteUri.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsTemplateWithoutSlashPrefixedPath()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("https://proxy.example?target=host"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsVariablesInPathAndQueryComponents()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}{?ipproto}");

        Assert.Contains("{target}", template.Template, StringComparison.Ordinal);
        Assert.Contains("{?ipproto}", template.Template, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsVariablesBeforePathAndQueryComponents()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("https://{target}.example/ip/{ipproto}/"));
    }
}
