// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class DnsServiceBindingSelectionTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0005")]
    [Requirement("REQ-QUIC-RFC9461-0035")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SelectEndpointsUsesSupportedAlpnProtocols()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"]);

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"]));

        DnsServiceBindingEndpoint endpoint = Assert.Single(endpoints);
        Assert.Equal(DnsServiceBindingProtocol.DnsOverQuic, endpoint.Protocol);
        Assert.Equal("doq", endpoint.AlpnProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0005")]
    [Requirement("REQ-QUIC-RFC9461-0035")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SelectEndpointsTreatsRecordsWithoutAlpnAsIncompatible()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create("resolver.example");

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"]));

        Assert.Empty(endpoints);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0006")]
    [Requirement("RFC9461-S5-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HttpAlpnRequiresDohPathAndSelectsDoHEndpoint()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "/dns-query{?dns}");

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["h3"]));

        DnsServiceBindingEndpoint endpoint = Assert.Single(endpoints);
        Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, endpoint.Protocol);
        Assert.Equal("/dns-query{?dns}", endpoint.DohPathTemplate);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0006")]
    [Requirement("RFC9461-S5-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HttpAlpnWithoutDohPathIsNotSelected()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"]);

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["h3"]));

        Assert.Empty(endpoints);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0007")]
    [Requirement("RFC9461-S5-P3-S2-R01")]
    [Requirement("REQ-QUIC-RFC9461-0037")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HttpsSvcParamsApplyToSelectedHttpConnection()
    {
        Dictionary<string, string> httpsParameters = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ech"] = "config",
        };
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h2"],
            dohPathTemplate: "/dns-query{?dns}",
            httpsServiceParameters: httpsParameters);

        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["h2"])));

        Assert.Equal("config", endpoint.HttpsServiceParameters["ech"]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0007")]
    [Requirement("RFC9461-S5-P3-S2-R01")]
    [Requirement("REQ-QUIC-RFC9461-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void HttpsSvcParamsDoNotApplyToNonHttpConnections()
    {
        Dictionary<string, string> httpsParameters = new(StringComparer.OrdinalIgnoreCase)
        {
            ["ech"] = "config",
        };
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            httpsServiceParameters: httpsParameters);

        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"])));

        Assert.Empty(endpoint.HttpsServiceParameters);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0008")]
    [Requirement("REQ-QUIC-RFC9461-0009")]
    [Requirement("REQ-QUIC-RFC9461-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SelectionSeparatesProtocolsByDefaultPortWhenPortIsOmitted()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq", "h3"],
            dohPathTemplate: "/dns-query{?dns}");

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq", "h3"]));

        Assert.Collection(
            endpoints,
            endpoint => Assert.Equal(853, endpoint.Port),
            endpoint => Assert.Equal(443, endpoint.Port));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SelectionDoesNotCollapseDifferentDefaultPortsWhenPortIsOmitted()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq", "h3"],
            dohPathTemplate: "/dns-query{?dns}");

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq", "h3"]));

        Assert.NotEqual(endpoints[0].Port, endpoints[1].Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PortKeyIsUsedWhenClientRespectsPortKey()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            port: 8853);

        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"], respectPortKey: true)));

        Assert.Equal(8853, endpoint.Port);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PortKeyCausesRecordToBeIgnoredWhenClientDoesNotRespectPortKey()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            port: 8853);

        IReadOnlyList<DnsServiceBindingEndpoint> endpoints = DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create(["doq"], respectPortKey: false));

        Assert.Empty(endpoints);
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-R01")]
    [Requirement("RFC9461-S5-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DohPathIsRelativeTemplateWithDnsVariable()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "/dns-query{?dns}");

        Assert.Equal("/dns-query{?dns}", record.DohPathTemplate);
    }

    [Theory]
    [InlineData("https://resolver.example/dns-query{?dns}")]
    [InlineData("//resolver.example/dns-query{?dns}")]
    [InlineData("/dns-query")]
    [InlineData("")]
    [Requirement("RFC9461-S5-P1-R01")]
    [Requirement("RFC9461-S5-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DohPathRejectsAbsoluteOrVariableLessTemplates(string dohPathTemplate)
    {
        Assert.Throws<ArgumentException>(() =>
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: dohPathTemplate));
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-S2-R02")]
    [Requirement("RFC9461-S5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DohPathExpansionProducesValidPathValue()
    {
        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query?dns={dns}"),
            DnsServiceBindingSelectionOptions.Create(["h3"])));

        string path = endpoint.ExpandDohPath([0x01, 0x02, 0x03]);

        Assert.Equal("/dns-query?dns=AQID", path);
    }

    [Fact]
    [Requirement("RFC9461-S5-P1-S2-R02")]
    [Requirement("RFC9461-S5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DohPathExpansionRejectsEmptyDnsMessages()
    {
        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query?dns={dns}"),
            DnsServiceBindingSelectionOptions.Create(["h3"])));

        Assert.Throws<ArgumentException>(() => endpoint.ExpandDohPath([]));
    }

    [Fact]
    [Requirement("RFC9461-S5-P2-S1-R01")]
    [Requirement("REQ-QUIC-RFC9461-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DohEndpointUsesHttpsOriginAuthenticationNameAndPort()
    {
        DnsServiceBindingEndpoint endpoint = Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            DnsServiceBindingRecord.Create(
                "Resolver.Example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query{?dns}",
                port: 8443),
            DnsServiceBindingSelectionOptions.Create(["h3"])));

        Assert.Equal("resolver.example", endpoint.AuthenticationName);
        Assert.Equal(8443, endpoint.Port);
        Assert.Equal(DnsServiceBindingProtocol.DnsOverHttps3, endpoint.Protocol);
    }

    [Fact]
    [Requirement("RFC9461-S5-P2-S1-R01")]
    [Requirement("REQ-QUIC-RFC9461-0034")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DohEndpointRejectsInvalidPortOrigin()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            DnsServiceBindingRecord.Create(
                "resolver.example",
                alpnProtocols: ["h3"],
                dohPathTemplate: "/dns-query{?dns}",
                port: 0));
    }
}
