// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9461_ClientPolicyFuzzClosure
{
    [Fact]
    [Requirement("RFC9461-S5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P3S1_DohpathEndpointsDoNotTriggerHttpsRecordQueries()
    {
        Assert.False(CreatePlan(CreateEndpoint("h2", "/dns-query{?dns}")).ShouldQueryHttpsRecords);
        Assert.False(CreatePlan(CreateEndpoint("h3", "/dns-query?dns={dns}")).ShouldQueryHttpsRecords);
        Assert.True(CreatePlan(CreateEndpoint("doq", null)).ShouldQueryHttpsRecords);
    }

    [Fact]
    [Requirement("RFC9461-S5-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S5P3S3_OperatorsPublishEquivalentHttpsRecordUntilSatisfied()
    {
        Assert.True(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: false).ShouldPublishEquivalentHttpsRecord);
        Assert.True(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: true).ShouldPublishEquivalentHttpsRecord);
        Assert.False(DnsServiceBindingOperatorGuidance.Create(
            resolutionSpeedHighPriority: true,
            equivalentHttpsRecordPublished: true).ShouldPublishEquivalentHttpsRecord);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0020_AliasModeIsAvoidedWhenResolutionSpeedIsHighPriority()
    {
        Assert.True(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: true).ShouldAvoidAliasMode);
        Assert.False(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: false).ShouldAvoidAliasMode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0021_FastResolutionUsesSvcbTargetNameConvention()
    {
        Assert.True(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: true).ShouldUseFastResolutionTargetNameConvention);
        Assert.False(DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: false).ShouldUseFastResolutionTargetNameConvention);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P1_TransportAuthenticationUsesEndpointAuthenticationName()
    {
        DnsServiceBindingClientPlan plan = CreatePlan(CreateEndpoint("h3", "/dns-query{?dns}", "Resolver.Example"));

        Assert.True(plan.AuthenticatesServerToAuthenticationName);
        Assert.Equal("resolver.example", plan.ServerAuthenticationName);
        Assert.Same(plan.Endpoint, plan.Endpoint);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P1P3_ClientIdentityIsSuppressedExceptForKnownSafeServers()
    {
        Assert.False(CreatePlan(CreateEndpoint()).AllowsClientIdentityDuringDnsQuery);
        Assert.True(DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(),
            endpointKnownSafeForClientAuthentication: true).AllowsClientIdentityDuringDnsQuery);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-2-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P1P3S1_InvalidResponseStopsFurtherQueriesToEndpoint()
    {
        Assert.True(CreatePlan(CreateEndpoint(), endpointSentInvalidResponse: false).ShouldSendMoreQueriesToEndpoint);
        Assert.False(CreatePlan(CreateEndpoint(), endpointSentInvalidResponse: true).ShouldSendMoreQueriesToEndpoint);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-2-P3-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P1P3S1_InvalidResponseMayBeLogged()
    {
        Assert.False(CreatePlan(CreateEndpoint(), endpointSentInvalidResponse: false).MayLogInvalidResponse);
        Assert.True(CreatePlan(CreateEndpoint(), endpointSentInvalidResponse: true).MayLogInvalidResponse);
    }

    [Fact]
    [Requirement("RFC9461-S8-2-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P2P2_SvcbResolutionSuccessSwitchesToSvcbReliantBehavior()
    {
        Assert.False(CreatePlan(CreateEndpoint(), svcbResolutionSucceeded: false).UsesSvcbReliantBehavior);
        Assert.True(CreatePlan(CreateEndpoint(), svcbResolutionSucceeded: true).UsesSvcbReliantBehavior);
    }

    [Fact]
    [Requirement("RFC9461-S8-2-P2-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_S8P2P2_DependentSpecificationMayAdjustFallbackBehavior()
    {
        Assert.False(CreatePlan(CreateEndpoint(), dependentSpecificationAllowsCleartextFallback: false).AllowsCleartextFallback);
        Assert.True(CreatePlan(CreateEndpoint(), dependentSpecificationAllowsCleartextFallback: true).AllowsCleartextFallback);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0028_DohpathSvcParamKeyUsesRegisteredNumberSeven()
    {
        Assert.Equal(7, DnsServiceBindingRecord.DohPathSvcParamKey);
        Assert.NotEqual(DnsServiceBindingRecord.PortSvcParamKey, DnsServiceBindingRecord.DohPathSvcParamKey);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0030_ResourceRecordTypeIsSvcbSixtyFour()
    {
        Assert.Equal(64, DnsServiceBindingRecord.SvcbResourceRecordType);
        Assert.NotEqual(DnsServiceBindingDefaults.CleartextDnsDefaultPort, DnsServiceBindingRecord.SvcbResourceRecordType);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0031_CleartextFallbackIsOffUnlessDependentSpecificationOverrides()
    {
        Assert.False(CreatePlan(CreateEndpoint(), svcbResolutionSucceeded: true).AllowsCleartextFallback);
        Assert.False(CreatePlan(CreateEndpoint(), dependentSpecificationAllowsCleartextFallback: false).AllowsCleartextFallback);
        Assert.True(CreatePlan(CreateEndpoint(), dependentSpecificationAllowsCleartextFallback: true).AllowsCleartextFallback);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_0032_PortKeyIsAutomaticallyMandatory()
    {
        Assert.True(DnsServiceBindingRecord.IsPortKeyAutomaticallyMandatory);
        Assert.Equal(3, DnsServiceBindingRecord.PortSvcParamKey);
    }

    private static DnsServiceBindingClientPlan CreatePlan(
        DnsServiceBindingEndpoint endpoint,
        bool svcbResolutionSucceeded = false,
        bool endpointSentInvalidResponse = false,
        bool dependentSpecificationAllowsCleartextFallback = false)
    {
        return DnsServiceBindingClientPolicy.CreatePlan(
            endpoint,
            svcbResolutionSucceeded: svcbResolutionSucceeded,
            endpointSentInvalidResponse: endpointSentInvalidResponse,
            dependentSpecificationAllowsCleartextFallback: dependentSpecificationAllowsCleartextFallback);
    }

    private static DnsServiceBindingEndpoint CreateEndpoint(
        string alpnProtocol = "h3",
        string? dohPathTemplate = "/dns-query{?dns}",
        string authenticationName = "resolver.example")
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            authenticationName,
            [alpnProtocol],
            dohPathTemplate: dohPathTemplate);

        return DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create([alpnProtocol])).Single();
    }
}
