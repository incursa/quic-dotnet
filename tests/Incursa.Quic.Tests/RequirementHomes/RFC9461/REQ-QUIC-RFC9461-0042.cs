// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.RFC9461;

public sealed class REQ_QUIC_RFC9461_0042
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0042")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CreatePublicationPlan_RendersSvcbAndEquivalentHttpsRecords()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "Resolver.Example",
            alpnProtocols: ["h3"],
            dohPathTemplate: "/dns-query{?dns}",
            port: 8443,
            httpsServiceParameters: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ech"] = "config",
            });
        DnsServiceBindingOperatorGuidance guidance =
            DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: true);

        DnsServiceBindingPublicationPlan plan = DnsServiceBindingPublicationPlan.Create(
            DnsServiceTransport.DnsOverHttps,
            record,
            "Target.Example",
            guidance,
            ttlSeconds: 600);

        Assert.True(plan.AvoidsAliasMode);
        Assert.True(plan.IncludesEquivalentHttpsRecord);
        Assert.Collection(
            plan.Records,
            svcb =>
            {
                Assert.Equal("_8443._dns.resolver.example.", svcb.OwnerName);
                Assert.Equal(64, svcb.ResourceRecordType);
                Assert.Equal("SVCB", svcb.ResourceRecordTypeName);
                Assert.Equal("_8443._dns.resolver.example. 600 IN SVCB 1 target.example. alpn=\"h3\" port=8443 dohpath=\"/dns-query{?dns}\" ech=\"config\"", svcb.ToPresentationString());
            },
            https =>
            {
                Assert.Equal("resolver.example.", https.OwnerName);
                Assert.Equal(65, https.ResourceRecordType);
                Assert.Equal("HTTPS", https.ResourceRecordTypeName);
                Assert.Equal("resolver.example. 600 IN HTTPS 1 target.example. alpn=\"h3\" port=8443 dohpath=\"/dns-query{?dns}\" ech=\"config\"", https.ToPresentationString());
            });
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9461-0042")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("", 300)]
    [InlineData("target..example", 300)]
    [InlineData("target.example", 0)]
    public void CreatePublicationPlan_RejectsInvalidTargetNamesAndTtls(string targetName, int ttlSeconds)
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            port: 853);

        Assert.ThrowsAny<ArgumentException>(() =>
            DnsServiceBindingPublicationPlan.Create(
                DnsServiceTransport.DnsOverQuic,
                record,
                targetName,
                ttlSeconds: ttlSeconds));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0042")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CreatePublicationPlan_OmitsEquivalentHttpsRecordWhenNoHttpProtocolIsPresent()
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            alpnProtocols: ["doq"],
            port: 853);

        DnsServiceBindingPublicationPlan plan = DnsServiceBindingPublicationPlan.Create(
            DnsServiceTransport.DnsOverQuic,
            record,
            "target.example.",
            DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: false));

        DnsServiceBindingPublicationRecord publication = Assert.Single(plan.Records);
        Assert.False(plan.IncludesEquivalentHttpsRecord);
        Assert.Equal("_853._dns.resolver.example. 300 IN SVCB 1 target.example. alpn=\"doq\" port=853", publication.ToPresentationString());
    }
}
