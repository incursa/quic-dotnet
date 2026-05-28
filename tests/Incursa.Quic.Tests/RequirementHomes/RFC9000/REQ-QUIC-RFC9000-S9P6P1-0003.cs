// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0003")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientPromotesThePreferredServerAddressAfterValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == preferredPath
            && !promote.RestoreSavedState);
        Assert.Equal(preferredPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClientDoesNotSendFuturePacketsToThePreferredAddressBeforeValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        QuicConnectionTransitionResult result = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.Equal(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path, runtime.ActivePath!.Value.Identity);
        Assert.NotEqual(preferredPath, runtime.ActivePath.Value.Identity);
        QuicS9P6P1PreferredAddressTestSupport.AssertCandidatePathPendingValidation(runtime, preferredPath);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ClientPromotesTheIpv6PreferredServerAddressAfterValidationSucceeds()
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6: true);

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 30);

        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == preferredPath);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
    }
}
