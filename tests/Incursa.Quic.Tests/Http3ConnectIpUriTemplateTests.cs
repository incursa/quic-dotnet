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

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AllowsOtherVariables()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{tenant}");
        Http3ConnectIpRequestTarget target = template.Expand("host.example", additionalVariables: new Dictionary<string, string> { ["tenant"] = "alpha" });

        Assert.Equal("/ip/host.example/alpha", target.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsUnresolvedOtherVariablesAtExpansion()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{tenant}");

        Assert.Throws<ArgumentException>(() => template.Expand("host.example"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0012")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AllowsTargetAndIpprotoVariables()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault("proxy.example");
        Http3ConnectIpRequestTarget target = template.Expand("host.example", "17");

        Assert.Equal("/.well-known/masque/ip/host.example/17/", target.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0012")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DoesNotRequireTargetAndIpprotoVariables()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/static");
        Http3ConnectIpRequestTarget target = template.Expand();

        Assert.Equal("/ip/static", target.PathAndQuery);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_ExpandsNonEmptyTargetAndIpprotoValues()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}{?ipproto}");
        Http3ConnectIpRequestTarget target = template.Expand("host.example", "17");

        Assert.Equal("/ip/host.example?ipproto=17", target.PathAndQuery);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("", "17")]
    [InlineData("host.example", "")]
    public void UriTemplate_RejectsEmptyTargetAndIpprotoValuesWhenIncluded(string targetValue, string ipprotoValue)
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault("proxy.example");

        Assert.Throws<ArgumentException>(() => template.Expand(targetValue, ipprotoValue));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsPrintableAsciiTemplates()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{ipproto}/");

        Assert.Equal("https://proxy.example/ip/{target}/{ipproto}/", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_RejectsNonPrintableAsciiTemplates()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/\u007f"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0015")]
    [Requirement("REQ-QUIC-RFC9484-0016")]
    [Requirement("REQ-QUIC-RFC9484-0017")]
    [Requirement("REQ-QUIC-RFC9484-0018")]
    [Requirement("REQ-QUIC-RFC9484-0019")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AcceptsSimpleExpansionInsteadOfForbiddenOperators()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/{ipproto}/");

        Assert.Equal("https://proxy.example/ip/{target}/{ipproto}/", template.Template);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0015")]
    [Requirement("REQ-QUIC-RFC9484-0016")]
    [Requirement("REQ-QUIC-RFC9484-0017")]
    [Requirement("REQ-QUIC-RFC9484-0018")]
    [Requirement("REQ-QUIC-RFC9484-0019")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("https://proxy.example/ip/{.target}/")]
    [InlineData("https://proxy.example/ip/{#target}/")]
    [InlineData("https://proxy.example/ip/{+target}/")]
    [InlineData("https://proxy.example/ip/{;target}/")]
    [InlineData("https://proxy.example/ip/{/target}/")]
    public void UriTemplate_RejectsForbiddenExpansionOperators(string template)
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(template));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0020")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AllowsGeneralPurposeImplementations()
    {
        Assert.True(Http3ConnectIpUriTemplate.GeneralPurposeUriTemplateImplementationAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0020")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_StillProvidesSpecificValidation()
    {
        Assert.True(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{target}/", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0021")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_RecommendsValidationBeforeUse()
    {
        Assert.True(Http3ConnectIpUriTemplate.ShouldValidateTemplateBeforeUse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0021")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DetectsInvalidTemplatesDuringValidation()
    {
        Assert.False(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{+target}/", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0022")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_AbortsRequestWhenTemplateInvalid()
    {
        Assert.True(Http3ConnectIpUriTemplate.AbortRequestWhenTemplateInvalid);
        Assert.False(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{+target}/", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0022")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DoesNotAbortRequestForValidTemplate()
    {
        Assert.True(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{target}/", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0023")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_CreatesDefaultTemplateForLimitedClients()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault("proxy.example:443");

        Assert.Equal("https://proxy.example:443/.well-known/masque/ip/{target}/{ipproto}/", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0023")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DefaultTemplateDoesNotPreventCustomTemplates()
    {
        Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.Create("https://proxy.example/custom/{target}/");

        Assert.Equal("https://proxy.example/custom/{target}/", template.Template);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0024")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UriTemplate_RecommendsOfferingDefaultTemplateForInteroperability()
    {
        Assert.True(Http3ConnectIpUriTemplate.ShouldOfferDefaultTemplateForInteroperability);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0024")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UriTemplate_DefaultLocationIsConcreteAndNotEmpty()
    {
        Assert.Equal("/.well-known/masque/ip/{target}/{ipproto}/", Http3ConnectIpUriTemplate.DefaultPathTemplate);
    }
}
