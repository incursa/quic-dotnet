// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0004")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientDiscontinuesUseOfTheOldServerAddressAfterPreferredAddressValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(runtime, preferredPath, observedAtTicks: 30);
        QuicConnectionTransitionResult oldAddressResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 40);

        Assert.False(oldAddressResult.StateChanged);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientKeepsTheOldServerAddressWhilePreferredAddressValidationIsPending()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicConnectionTransitionResult oldAddressResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 30);

        Assert.True(oldAddressResult.StateChanged);
        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        Assert.NotEqual(preferredPath, runtime.ActivePath.Value.Identity);
        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientDiscontinuesTheOldIpv6ServerAddressAfterIpv6PreferredAddressValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true);

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(runtime, preferredPath, observedAtTicks: 30);
        QuicConnectionTransitionResult oldAddressResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 40);

        Assert.False(oldAddressResult.StateChanged);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
    }
}
