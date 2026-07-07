// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_FoundationUriTemplateFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectIpMechanismRejectsAnyIpHeaderFieldConveyance()
    {
        foreach ((bool conveysIpHeaderFields, bool tunnelsOtherIpProtocols) in new[]
        {
            (true, false),
            (true, true),
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
                    conveysIpHeaderFields,
                    tunnelsOtherIpProtocols));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
            Assert.Contains("IP header fields", exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectIpMechanismRejectsAnyOtherIpProtocolTunneling()
    {
        foreach ((bool conveysIpHeaderFields, bool tunnelsOtherIpProtocols) in new[]
        {
            (false, true),
            (true, true),
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpFoundationPolicy.ValidatePayloadMechanismScope(
                    conveysIpHeaderFields,
                    tunnelsOtherIpProtocols));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectIpVariableLengthIntegersRoundTripAtEncodingBoundaries()
    {
        foreach (ulong value in new[] { 0UL, 1UL, 63UL, 64UL, 15293UL, 16383UL, 16384UL, 1_073_741_823UL })
        {
            byte[] encoded = Http3ConnectIpFoundationPolicy.EncodeVariableLengthInteger(value);

            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(encoded, out ulong decoded, out int bytesConsumed));
            Assert.Equal(value, decoded);
            Assert.Equal(encoded.Length, bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectIpDecoderAcceptsNonMinimalVariableLengthIntegerEncodings()
    {
        foreach ((byte[] encoded, ulong expectedValue, int expectedLength) in new (byte[], ulong, int)[]
        {
            ([0x40, 0x01], 1, 2),
            ([0x80, 0x00, 0x00, 0x25], 37, 4),
            ([0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25], 37, 8),
        })
        {
            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(encoded, out ulong value, out int bytesConsumed));
            Assert.Equal(expectedValue, value);
            Assert.Equal(expectedLength, bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectIpStreamReferenceScopeTracksHttpMultiplexingCapability()
    {
        foreach ((bool multiplexesStreams, Http3ConnectIpStreamReferenceScope expectedScope) in new[]
        {
            (false, Http3ConnectIpStreamReferenceScope.EntireConnection),
            (true, Http3ConnectIpStreamReferenceScope.RequestStream),
        })
        {
            Assert.Equal(expectedScope, Http3ConnectIpFoundationPolicy.GetStreamReferenceScope(multiplexesStreams));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRequiresSlashPrefixedPathComponent()
    {
        foreach (string template in new[]
        {
            "https://proxy.example?target=host",
            "https://proxy.example",
            "https://proxy.example#fragment",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(template));
        }

        Assert.StartsWith("/", Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}").AbsoluteUri.AbsolutePath, StringComparison.Ordinal);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateVariablesAreRestrictedToPathAndQuery()
    {
        foreach (string invalidTemplate in new[]
        {
            "https://{target}.example/ip/{ipproto}/",
            "https://proxy.{tenant}/ip/{target}/",
            "{scheme}://proxy.example/ip/{target}/",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(invalidTemplate));
        }

        Assert.True(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{target}{?ipproto}", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateAllowsAdditionalVariablesWhenCallerSuppliesValues()
    {
        foreach ((string template, Dictionary<string, string> variables, string expectedPath) in new[]
        {
            ("https://proxy.example/ip/{target}/{tenant}", new Dictionary<string, string> { ["tenant"] = "alpha" }, "/ip/host.example/alpha"),
            ("https://proxy.example/ip/{target}/{tenant}/{zone}", new Dictionary<string, string> { ["tenant"] = "alpha", ["zone"] = "z1" }, "/ip/host.example/alpha/z1"),
        })
        {
            Http3ConnectIpRequestTarget target = Http3ConnectIpUriTemplate.Create(template).Expand("host.example", additionalVariables: variables);

            Assert.Equal(expectedPath, target.PathAndQuery);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateExpandsTargetAndIpprotoVariablesWhenPresent()
    {
        foreach ((string target, string ipproto, string expected) in new[]
        {
            ("host.example", "17", "/.well-known/masque/ip/host.example/17/"),
            ("2001:db8::1", "58", "/.well-known/masque/ip/2001%3Adb8%3A%3A1/58/"),
        })
        {
            Http3ConnectIpRequestTarget requestTarget = Http3ConnectIpUriTemplate.CreateDefault("proxy.example").Expand(target, ipproto);

            Assert.Equal(expected, requestTarget.PathAndQuery);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRejectsEmptyTargetAndIpprotoValuesWhenVariablesExist()
    {
        foreach ((string? target, string? ipproto) in new[]
        {
            ("", "17"),
            ("host.example", ""),
            (null, "17"),
            ("host.example", null),
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.CreateDefault("proxy.example").Expand(target, ipproto));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateAllowsOnlyPrintableAsciiCharacters()
    {
        foreach (string invalidTemplate in new[]
        {
            "https://proxy.example/ip/{target}/\u0000",
            "https://proxy.example/ip/{target}/\u001f",
            "https://proxy.example/ip/{target}/ ",
            "https://proxy.example/ip/{target}/\u007f",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(invalidTemplate));
        }

        Assert.True(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{target}/~ok", out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsDotPrefixLabelExpansion()
    {
        AssertForbiddenOperator("{.target}");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsFragmentExpansion()
    {
        AssertForbiddenOperator("{#target}");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsReservedExpansion()
    {
        AssertForbiddenOperator("{+target}");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsPathStyleParameterExpansion()
    {
        AssertForbiddenOperator("{;target}");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateForbidsPathSegmentExpansion()
    {
        AssertForbiddenOperator("{/target}");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateAllowsGeneralPurposeImplementationsBehindStrictValidation()
    {
        foreach (string template in new[]
        {
            "https://proxy.example/ip/{target}/",
            "https://proxy.example/ip/{target}{?ipproto}",
        })
        {
            Assert.True(Http3ConnectIpUriTemplate.GeneralPurposeUriTemplateImplementationAllowed);
            Assert.True(Http3ConnectIpUriTemplate.TryCreate(template, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateValidationDetectsInvalidTemplatesBeforeUse()
    {
        foreach (string invalidTemplate in new[]
        {
            "https://proxy.example/ip/{+target}/",
            "https://{target}.example/ip/",
            "https://proxy.example",
        })
        {
            Assert.True(Http3ConnectIpUriTemplate.ShouldValidateTemplateBeforeUse);
            Assert.False(Http3ConnectIpUriTemplate.TryCreate(invalidTemplate, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateInvalidConfigurationsAbortRequestLocally()
    {
        foreach (string invalidTemplate in new[]
        {
            "/ip/{target}/",
            "https://proxy.example/ip/{#target}/",
        })
        {
            Assert.True(Http3ConnectIpUriTemplate.AbortRequestWhenTemplateInvalid);
            Assert.False(Http3ConnectIpUriTemplate.TryCreate(invalidTemplate, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateDefaultTemplateSupportsLimitedClients()
    {
        foreach ((string authority, string scheme, string expected) in new[]
        {
            ("proxy.example", "https", "https://proxy.example/.well-known/masque/ip/{target}/{ipproto}/"),
            ("proxy.example:8443", "https", "https://proxy.example:8443/.well-known/masque/ip/{target}/{ipproto}/"),
            ("gateway.example", "http", "http://gateway.example/.well-known/masque/ip/{target}/{ipproto}/"),
        })
        {
            Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault(authority, scheme);

            Assert.Equal(expected, template.Template);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateDefaultServiceLocationIsConcreteAndExpandable()
    {
        foreach (string authority in new[] { "proxy.example", "proxy.example:443", "gateway.example:8443" })
        {
            Http3ConnectIpUriTemplate template = Http3ConnectIpUriTemplate.CreateDefault(authority);
            Http3ConnectIpRequestTarget target = template.Expand("host.example", "17");

            Assert.True(Http3ConnectIpUriTemplate.ShouldOfferDefaultTemplateForInteroperability);
            Assert.Equal("/.well-known/masque/ip/{target}/{ipproto}/", Http3ConnectIpUriTemplate.DefaultPathTemplate);
            Assert.Equal("/.well-known/masque/ip/host.example/17/", target.PathAndQuery);
        }
    }

    [Fact]
    [Requirement("RFC9484-S3-P5-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateMustBeAbsoluteForm()
    {
        foreach (string template in new[] { "/ip/{target}/", "proxy.example/ip/{target}/", "//proxy.example/ip/{target}/" })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(template));
        }

        Assert.Equal("proxy.example", Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/").ProxyAuthority);
    }

    [Fact]
    [Requirement("RFC9484-S3-P6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRejectsLevelFourOperators()
    {
        foreach (string forbiddenOperator in new[] { "{.target}", "{#target}", "{+target}", "{;target}", "{/target}" })
        {
            AssertForbiddenOperator(forbiddenOperator);
        }
    }

    [Fact]
    [Requirement("RFC9484-S3-P7-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UriTemplateRequiresNonEmptySchemeAuthorityAndPath()
    {
        foreach (string template in new[]
        {
            "https://proxy.example",
            "https:///ip/{target}/",
            "://proxy.example/ip/{target}/",
        })
        {
            Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create(template));
        }

        Http3ConnectIpUriTemplate valid = Http3ConnectIpUriTemplate.Create("https://proxy.example/ip/{target}/");
        Assert.Equal("https", valid.AbsoluteUri.Scheme);
        Assert.Equal("proxy.example", valid.AbsoluteUri.Authority);
        Assert.Equal("/ip/x/", valid.AbsoluteUri.AbsolutePath);
    }

    private static void AssertForbiddenOperator(string forbiddenOperator)
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpUriTemplate.Create($"https://proxy.example/ip/{forbiddenOperator}/"));
        Assert.True(Http3ConnectIpUriTemplate.TryCreate("https://proxy.example/ip/{target}/", out _));
    }
}
