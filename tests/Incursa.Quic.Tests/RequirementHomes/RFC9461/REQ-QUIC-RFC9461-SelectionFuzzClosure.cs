// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9461_SelectionFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0005_RecordsWithoutAlpnRemainIncompatibleUnlessEquivalentKeyIsPresent()
    {
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example"), ["doq"]));
        Assert.Empty(Select(
            DnsServiceBindingRecord.Create("resolver.example", hasEquivalentSupportedProtocolKey: true),
            ["doq"]));

        DnsServiceBindingEndpoint endpoint = Assert.Single(Select(
            DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: [" DoQ "]),
            ["doq"]));
        Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, endpoint.Protocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0006_HttpAlpnProtocolsRequireDohPath()
    {
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h2"]), ["h2"]));
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h3"]), ["h3"]));

        Assert.Collection(
            Select(
                DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h2", "h3"], dohPathTemplate: "/dns-query{?dns}"),
                ["h2", "h3"]),
            endpoint => Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps2, endpoint.Protocol),
            endpoint => Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, endpoint.Protocol));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0007_HttpsSvcParamsApplyOnlyToResultingHttpConnections()
    {
        Dictionary<string, string> parameters = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ech"] = "config",
            ["ipv4hint"] = "192.0.2.10",
        };
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq", "h2", "h3"],
            dohPathTemplate: "/dns-query{?dns}",
            httpsServiceParameters: parameters);

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = Select(record, ["doq", "h2", "h3"]);

        Assert.Empty(endpoints.Single(endpoint => endpoint.Protocol == DnsServiceBindingProtocol.DnsOverQuic).HttpsServiceParameters);
        Assert.Equal("config", endpoints.Single(endpoint => endpoint.Protocol == DnsServiceBindingProtocol.DnsOverHttps2).HttpsServiceParameters["ech"]);
        Assert.Equal("192.0.2.10", endpoints.Single(endpoint => endpoint.Protocol == DnsServiceBindingProtocol.DnsOverHttps3).HttpsServiceParameters["ipv4hint"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0008_OmittedPortKeepsProtocolsOnTheirDefaultPorts()
    {
        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = Select(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["dot", "doq", "h2", "h3"],
                dohPathTemplate: "/dns-query{?dns}"),
            ["dot", "doq", "h2", "h3"]);

        Assert.Equal([853, 853, 443, 443], endpoints.Select(endpoint => endpoint.Port).ToArray());
        Assert.Equal(2, endpoints.Select(endpoint => endpoint.Port).Distinct().Count());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0009_DefaultPortIsPerTransportProtocolWhenPortIsOmitted()
    {
        Assert.Equal(853, SelectSingle("dot", null).Port);
        Assert.Equal(853, SelectSingle("doq", null).Port);
        Assert.Equal(443, SelectSingle("h2", "/dns-query{?dns}").Port);
        Assert.Equal(443, SelectSingle("h3", "/dns-query{?dns}").Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0010_PortKeyIsIgnoredUnlessClientRespectsIt()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            port: 8853);

        Assert.Empty(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"], respectPortKey: false)));
        Assert.Equal(8853, DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"], respectPortKey: true)).Single().Port);
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P1_DohPathIsSingleValuedRelativeUtf8Template()
    {
        Assert.Equal("/dns-query{?dns}", DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "/dns-query{?dns}").DohPathTemplate);

        Assert.Throws<ArgumentException>(() => DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "https://resolver.example/dns-query{?dns}"));
        Assert.Throws<ArgumentException>(() => DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: string.Empty));
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P1S1_HttpAlpnSupportRequiresDohPath()
    {
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h2"]), ["h2"]));
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h3"]), ["h3"]));
        Assert.Equal("/dns-query{?dns}", Select(
            DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["h3"], dohPathTemplate: "/dns-query{?dns}"),
            ["h3"]).Single().DohPathTemplate);
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P1S2_DohPathTemplateContainsDnsVariable()
    {
        Assert.Throws<ArgumentException>(() => DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "/dns-query"));
        Assert.EndsWith("?dns=AQI", SelectSingle("h3", "/dns-query{?dns}").ExpandDohPath([0x01, 0x02]), StringComparison.Ordinal);
        Assert.Equal("/dns/AQI", SelectSingle("h3", "/dns/{dns}").ExpandDohPath([0x01, 0x02]));
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-S2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P1S2_DohPathTemplateExpandsToValidPathValue()
    {
        DnsServiceBindingEndpoint endpoint = SelectSingle("h3", "/dns-query?dns={dns}");

        Assert.Equal("/dns-query?dns=AQIDBA", endpoint.ExpandDohPath([0x01, 0x02, 0x03, 0x04]));
        Assert.Throws<ArgumentException>(() => endpoint.ExpandDohPath([]));
        Assert.Throws<InvalidOperationException>(() => SelectSingle("doq", null).ExpandDohPath([0x01]));
    }

    [Fact]
    [Requirement("RFC9461-S5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P2S1_DohRequestsUseHttpsOriginAuthenticationNameAndPort()
    {
        DnsServiceBindingEndpoint defaultPort = SelectSingle("h3", "/dns-query{?dns}");
        DnsServiceBindingEndpoint explicitPort = Select(
            DnsServiceBindingRecord.Create("Resolver.Example", alpnProtocols: ["h2"], dohPathTemplate: "/dns-query{?dns}", port: 8443),
            ["h2"]).Single();

        Assert.Equal("resolver.example", defaultPort.AuthenticationName);
        Assert.Equal(443, defaultPort.Port);
        Assert.Equal("resolver.example", explicitPort.AuthenticationName);
        Assert.Equal(8443, explicitPort.Port);
    }

    [Fact]
    [Requirement("RFC9461-S5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P2S2_HttpRequestsUseExpandedDohPathResource()
    {
        Assert.Equal("/dns-query?dns=qrvM", SelectSingle("h2", "/dns-query?dns={dns}").ExpandDohPath([0xAA, 0xBB, 0xCC]));
        Assert.Equal("/dns-query?dns=qrvM", SelectSingle("h3", "/dns-query{?dns}").ExpandDohPath([0xAA, 0xBB, 0xCC]));
    }

    [Fact]
    [Requirement("RFC9461-S5-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P3S2_SvcParamsAreCarriedToHttpsConnections()
    {
        Dictionary<string, string> parameters = new(StringComparer.OrdinalIgnoreCase)
        {
            ["mandatory"] = "alpn,dohpath",
            ["ech"] = "config",
        };

        DnsServiceBindingEndpoint endpoint = Select(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query{?dns}",
                httpsServiceParameters: parameters),
            ["h3"]).Single();

        Assert.Equal("alpn,dohpath", endpoint.HttpsServiceParameters["mandatory"]);
        Assert.Equal("config", endpoint.HttpsServiceParameters["ech"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0034_DnsMappingOverridesGenericHttpsRecordForDoh()
    {
        DnsServiceBindingEndpoint endpoint = Select(
            DnsServiceBindingRecord.Create(
                "Resolver.Example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query{?dns}",
                port: 5443),
            ["h3"]).Single();

        Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, endpoint.Protocol);
        Assert.Equal("resolver.example", endpoint.AuthenticationName);
        Assert.Equal(5443, endpoint.Port);
        Assert.Equal("/dns-query?dns=AQ", endpoint.ExpandDohPath([0x01]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0035")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0035_MappingRequiresAlpnOrEquivalentKey()
    {
        Assert.Empty(Select(DnsServiceBindingRecord.Create("resolver.example"), ["doq"]));

        DnsServiceBindingRecord equivalentOnly = DnsServiceBindingRecord.Create(
            "resolver.example",
            hasEquivalentSupportedProtocolKey: true);
        Assert.Empty(Select(equivalentOnly, ["doq"]));

        Assert.Single(Select(DnsServiceBindingRecord.Create("resolver.example", alpnProtocols: ["doq"]), ["doq"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0037")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0037_MappingSupportsHttpsRecordSvcParamKeysForHttpEndpoints()
    {
        Dictionary<string, string> parameters = new(StringComparer.OrdinalIgnoreCase)
        {
            ["alpn"] = "h3",
            ["ipv6hint"] = "2001:db8::1",
        };

        DnsServiceBindingEndpoint endpoint = Select(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query{?dns}",
                httpsServiceParameters: parameters),
            ["h3"]).Single();

        Assert.Equal("h3", endpoint.HttpsServiceParameters["alpn"]);
        Assert.Equal("2001:db8::1", endpoint.HttpsServiceParameters["ipv6hint"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0038_DefaultPortIsPerTransport()
    {
        Assert.Equal(853, SelectSingle("dot", null).Port);
        Assert.Equal(853, SelectSingle("doq", null).Port);
        Assert.Equal(443, SelectSingle("h2", "/dns-query{?dns}").Port);
        Assert.Equal(443, SelectSingle("h3", "/dns-query{?dns}").Port);
    }

    private static DnsServiceBindingEndpoint SelectSingle(string alpnProtocol, string? dohPathTemplate)
    {
        return Select(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: [alpnProtocol],
                dohPathTemplate: dohPathTemplate),
            [alpnProtocol]).Single();
    }

    private static IReadOnlyList<DnsServiceBindingEndpoint> Select(
        DnsServiceBindingRecord record,
        string[] supportedAlpnProtocols)
    {
        return DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(supportedAlpnProtocols));
    }
}
