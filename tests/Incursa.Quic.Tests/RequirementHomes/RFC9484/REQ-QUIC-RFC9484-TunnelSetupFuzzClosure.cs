// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Incursa.Qpack;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_TunnelSetupFuzzClosure
{
    [Fact]
    [Requirement("RFC9484-S4-1-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyExtractsDecodedTargetAndIpprotoVariables()
    {
        foreach ((string? target, string? ipproto) in new[] { ("host.example", "17"), ("192.0.2.0/24", "6"), ("2001:db8::/64", "*"), (null, null) })
        {
            Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables(target, ipproto);

            Assert.NotNull(variables.Target);
            Assert.NotNull(variables.Ipproto);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidDecodedTunnelVariablesAreMalformed()
    {
        foreach ((string? target, string? ipproto) in new[] { ("192.0.2.1/24", "17"), ("host example", "17"), ("host.example", "256"), ("host.example", "udp") })
        {
            AssertMessageError(() => Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables(target, ipproto));
        }

        Http3ConnectIpTunnelVariables variables = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("192.0.2.0/24", "17");
        Assert.Equal(24, variables.Target.PrefixLength);
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DecodedTunnelVariablesAreValidatedAgainstScopeRules()
    {
        Http3ConnectIpTunnelVariables prefix = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("2001:db8::/64", "*");
        Http3ConnectIpTunnelVariables host = Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("host.example", "132");

        Assert.Equal(64, prefix.Target.PrefixLength);
        Assert.True(prefix.Ipproto.AllowsAnyProtocol);
        Assert.Equal("host.example", host.Target.HostName);
        Assert.Equal(132, host.Ipproto.ProtocolNumber);
        AssertMessageError(() => Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("2001:db8::1/64", "*"));
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DnsTargetsRequireResolutionBeforeHttpResponse()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(
            Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("host.example", "17")));

        Assert.False(Http3ConnectIpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(
            Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("192.0.2.0/24", "17")));

        Assert.False(Http3ConnectIpTunnelSetupPolicy.RequiresDnsResolutionBeforeResponse(
            Http3ConnectIpTunnelSetupPolicy.ValidateTunnelVariables("*", "*")));
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TunnelSetupErrorsRejectTheRequest()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(variableValidationFailed: true, dnsResolutionFailed: false, tunnelEstablishmentFailed: false));
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(variableValidationFailed: false, dnsResolutionFailed: true, tunnelEstablishmentFailed: false));
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(variableValidationFailed: false, dnsResolutionFailed: false, tunnelEstablishmentFailed: true));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldRejectSetup(variableValidationFailed: false, dnsResolutionFailed: false, tunnelEstablishmentFailed: false));
    }

    [Fact]
    [Requirement("RFC9484-S4-1-P3-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TunnelSetupErrorsCanIncludeProxyStatusDetails()
    {
        foreach (string errorType in new[] { "dns_error", "connection_refused", "policy_denied" })
        {
            IReadOnlyList<QPackFieldLine> headers = Http3ConnectIpTunnelSetupPolicy.BuildSetupErrorResponseHeaders(errorType);

            Assert.Contains(headers, header => header.Name == ":status" && header.Value == "502");
            Assert.Contains(headers, header => header.Name == "proxy-status" && header.Value == $"error={errorType}");
        }

        Assert.Throws<ArgumentException>(() => Http3ConnectIpTunnelSetupPolicy.CreateSetupErrorProxyStatusHeader(""));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0037")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TunnelLifetimeIsTiedToRequestStream()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(requestStreamOpen: true, tunnelEstablished: true, inactivityTimeoutElapsed: false));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(requestStreamOpen: false, tunnelEstablished: true, inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignmentsRemainWhileRequestStreamIsOpen()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(requestStreamOpen: true, tunnelEstablished: true, inactivityTimeoutElapsed: false));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(requestStreamOpen: true, tunnelEstablished: false, inactivityTimeoutElapsed: false));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldMaintainAssignments(requestStreamOpen: true, tunnelEstablished: true, inactivityTimeoutElapsed: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0039")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TunnelMayTearDownAfterInactivity()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.CanTearDownTunnelAfterInactivity(inactivityTimeoutElapsed: true));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.CanTearDownTunnelAfterInactivity(inactivityTimeoutElapsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0040")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InactivityTeardownClosesRequestStream()
    {
        Assert.True(Http3ConnectIpTunnelSetupPolicy.ShouldCloseRequestStreamWhenTearingDown(tearingDownTunnel: true));
        Assert.False(Http3ConnectIpTunnelSetupPolicy.ShouldCloseRequestStreamWhenTearingDown(tearingDownTunnel: false));
    }

    private static void AssertMessageError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);
        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }
}
