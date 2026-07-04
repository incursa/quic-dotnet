// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpTunnelSetupPolicyTests
{
    [Fact]
    [Requirement("RFC9484-S4-1-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_ExtractsDecodedTargetAndIpprotoVariables()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("host.example", "17");

        Assert.Equal("host.example", variables.Target.HostName);
        Assert.Equal(17, variables.Ipproto.ProtocolNumber);
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_AllowsOmittedOptionalTunnelVariables()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables(null, null);

        Assert.True(variables.Target.IsWildcard);
        Assert.True(variables.Ipproto.AllowsAnyProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0032")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_TreatsInvalidTunnelVariablesAsMalformed()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("192.0.2.1/24", "17"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0032")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotTreatValidTunnelVariablesAsMalformed()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("192.0.2.0/24", "17");

        Assert.Equal(24, variables.Target.PrefixLength);
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_ValidatesDecodedTunnelVariablesAgainstSection46()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("2001:db8::/64", "*");

        Assert.Equal(64, variables.Target.PrefixLength);
        Assert.True(variables.Ipproto.AllowsProtocol(132));
    }

    [Theory]
    [Requirement("RFC9484-S4-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("2001:db8::1/64", "*")]
    [InlineData("host example", "17")]
    [InlineData("host.example", "256")]
    public void TunnelSetup_RejectsVariablesThatFailSection46Validation(string target, string ipproto)
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables(target, ipproto));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_RequiresDnsResolutionBeforeResponseForDnsTargets()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("host.example", "17");

        Assert.True(Http3ConnectIpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(variables));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0034")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotRequireDnsResolutionForIpTargets()
    {
        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("192.0.2.0/24", "17");

        Assert.False(Http3ConnectIpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(variables));
    }

    [Theory]
    [Requirement("RFC9484-S4-1-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, false, false)]
    [InlineData(false, true, false)]
    [InlineData(false, false, true)]
    public void TunnelSetup_RejectsRequestsWhenProcessingErrorsOccur(bool variableValidationFailed, bool dnsResolutionFailed, bool tunnelEstablishmentFailed)
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(
            variableValidationFailed,
            dnsResolutionFailed,
            tunnelEstablishmentFailed));
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotRejectRequestWithoutProcessingErrors()
    {
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(
            variableValidationFailed: false,
            dnsResolutionFailed: false,
            tunnelEstablishmentFailed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0036")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_AddsProxyStatusDetailsOnErrors()
    {
        IReadOnlyList<QPackFieldLine> headers = Http3ConnectIpTunnelSetupPolicy.BuildSetupErrorResponseHeaders("dns_error");

        Assert.Contains(headers, header => header.Name == ":status" && header.Value == "502");
        Assert.Contains(headers, header => header.Name == "proxy-status" && header.Value == "error=dns_error");
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0036")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_RejectsEmptyProxyStatusErrorType()
    {
        Assert.Throws<ArgumentException>(() => Http3ConnectIpTunnelSetupPolicy.CreateSetupErrorProxyStatusHeader(""));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0037")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_TiesTunnelLifetimeToOpenRequestStream()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(
            requestStreamOpen: true,
            tunnelEstablished: true,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0037")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotMaintainTunnelAfterRequestStreamCloses()
    {
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(
            requestStreamOpen: false,
            tunnelEstablished: true,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0038")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_MaintainsAssignmentsWhileRequestStreamIsOpen()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(
            requestStreamOpen: true,
            tunnelEstablished: true,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0038")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_RemovesAssignmentsWhenTunnelIsNotEstablished()
    {
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(
            requestStreamOpen: true,
            tunnelEstablished: false,
            inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0039")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_CanTearDownTunnelAfterInactivity()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.CanTearDownTunnelAfterInactivity(inactivityTimeoutElapsed: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0039")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotTearDownTunnelBeforeInactivity()
    {
        Assert.False(Http3ConnectIpTunnelSetupPolicy.CanTearDownTunnelAfterInactivity(inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0040")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TunnelSetup_ClosesRequestStreamWhenTearingDownTunnel()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldCloseRequestStreamWhenTearingDown(tearingDownTunnel: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0040")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TunnelSetup_DoesNotCloseRequestStreamWithoutTunnelTeardown()
    {
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldCloseRequestStreamWhenTearingDown(tearingDownTunnel: false));
    }
}
