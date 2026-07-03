// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class DnsServiceBindingClientPolicyTests
{
    [Fact]
    [Requirement("RFC9461-S5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DohPathEndpointDoesNotQueryHttpsRecords()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(dohPathTemplate: "/dns-query{?dns}"));

        Assert.False(plan.ShouldQueryHttpsRecords);
    }

    [Fact]
    [Requirement("RFC9461-S5-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointWithoutDohPathCanQueryHttpsRecords()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(alpnProtocol: "doq"));

        Assert.True(plan.ShouldQueryHttpsRecords);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0019")]
    [Requirement("REQ-QUIC-RFC9461-0020")]
    [Requirement("REQ-QUIC-RFC9461-0021")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperatorGuidancePublishesHttpsAndAvoidsAliasModeForFastResolution()
    {
        DnsServiceBindingOperatorGuidance guidance =
            DnsServiceBindingOperatorGuidance.Create(resolutionSpeedHighPriority: true);

        Assert.True(guidance.ShouldPublishEquivalentHttpsRecord);
        Assert.True(guidance.ShouldAvoidAliasMode);
        Assert.True(guidance.ShouldUseFastResolutionTargetNameConvention);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0019")]
    [Requirement("REQ-QUIC-RFC9461-0020")]
    [Requirement("REQ-QUIC-RFC9461-0021")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperatorGuidanceDoesNotRepeatSatisfiedHttpsOrFastResolutionGuidance()
    {
        DnsServiceBindingOperatorGuidance guidance =
            DnsServiceBindingOperatorGuidance.Create(
                resolutionSpeedHighPriority: false,
                equivalentHttpsRecordPublished: true);

        Assert.False(guidance.ShouldPublishEquivalentHttpsRecord);
        Assert.False(guidance.ShouldAvoidAliasMode);
        Assert.False(guidance.ShouldUseFastResolutionTargetNameConvention);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-P2-R01")]
    [Requirement("RFC9461-S8-1-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SecurePlanAuthenticatesServerNameAndSuppressesDnsQueryIdentity()
    {
        DnsServiceBindingEndpoint endpoint = CreateEndpoint();

        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(endpoint);

        Assert.True(plan.AuthenticatesServerToAuthenticationName);
        Assert.Equal(endpoint.AuthenticationName, plan.ServerAuthenticationName);
        Assert.False(plan.AllowsClientIdentityDuringDnsQuery);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-P2-R01")]
    [Requirement("RFC9461-S8-1-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void KnownSafeEndpointCanAllowDnsQueryClientIdentity()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(),
            endpointKnownSafeForClientAuthentication: true);

        Assert.True(plan.AuthenticatesServerToAuthenticationName);
        Assert.True(plan.AllowsClientIdentityDuringDnsQuery);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-2-P3-S1-R01")]
    [Requirement("RFC9461-S8-1-2-P3-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InvalidResponseStopsFurtherQueriesAndMayBeLogged()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(),
            endpointSentInvalidResponse: true);

        Assert.False(plan.ShouldSendMoreQueriesToEndpoint);
        Assert.True(plan.MayLogInvalidResponse);
    }

    [Fact]
    [Requirement("RFC9461-S8-1-2-P3-S1-R01")]
    [Requirement("RFC9461-S8-1-2-P3-S1-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointWithoutInvalidResponseCanContinueWithoutErrorLog()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(CreateEndpoint());

        Assert.True(plan.ShouldSendMoreQueriesToEndpoint);
        Assert.False(plan.MayLogInvalidResponse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0026")]
    [Requirement("REQ-QUIC-RFC9461-0027")]
    [Requirement("REQ-QUIC-RFC9461-0031")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SuccessfulSvcbResolutionUsesSvcbBehaviorAndDiscouragesCleartextFallback()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(),
            svcbResolutionSucceeded: true);

        Assert.True(plan.UsesSvcbReliantBehavior);
        Assert.False(plan.AllowsCleartextFallback);
        Assert.False(plan.DependentSpecificationAllowsCleartextFallback);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0026")]
    [Requirement("REQ-QUIC-RFC9461-0027")]
    [Requirement("REQ-QUIC-RFC9461-0031")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DependentSpecificationCanAdjustFallbackBehavior()
    {
        DnsServiceBindingClientPlan plan = DnsServiceBindingClientPolicy.CreatePlan(
            CreateEndpoint(),
            dependentSpecificationAllowsCleartextFallback: true);

        Assert.False(plan.UsesSvcbReliantBehavior);
        Assert.True(plan.AllowsCleartextFallback);
        Assert.True(plan.DependentSpecificationAllowsCleartextFallback);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0028")]
    [Requirement("REQ-QUIC-RFC9461-0030")]
    [Requirement("REQ-QUIC-RFC9461-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RegistryConstantsExposeDohpathSvcbAndMandatoryPort()
    {
        Assert.Equal(7, DnsServiceBindingRecord.DohPathSvcParamKey);
        Assert.Equal(64, DnsServiceBindingRecord.SvcbResourceRecordType);
        Assert.Equal(3, DnsServiceBindingRecord.PortSvcParamKey);
        Assert.True(DnsServiceBindingRecord.IsPortKeyAutomaticallyMandatory);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9461-0028")]
    [Requirement("REQ-QUIC-RFC9461-0030")]
    [Requirement("REQ-QUIC-RFC9461-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RegistryConstantsDoNotUseUnknownOrCleartextValues()
    {
        Assert.NotEqual(0, DnsServiceBindingRecord.DohPathSvcParamKey);
        Assert.NotEqual(DnsServiceBindingDefaults.CleartextDnsDefaultPort, DnsServiceBindingRecord.SvcbResourceRecordType);
        Assert.NotEqual(DnsServiceBindingRecord.DohPathSvcParamKey, DnsServiceBindingRecord.PortSvcParamKey);
    }

    private static DnsServiceBindingEndpoint CreateEndpoint(
        string alpnProtocol = "h3",
        string? dohPathTemplate = null)
    {
        DnsServiceBindingRecord record = DnsServiceBindingRecord.Create(
            "resolver.example",
            [alpnProtocol],
            dohPathTemplate: dohPathTemplate ?? (alpnProtocol is "h2" or "h3" ? "/dns-query{?dns}" : null),
            port: 853);

        return Assert.Single(DnsServiceBindingSelector.SelectEndpoints(
            record,
            DnsServiceBindingSelectionOptions.Create([alpnProtocol])));
    }
}
