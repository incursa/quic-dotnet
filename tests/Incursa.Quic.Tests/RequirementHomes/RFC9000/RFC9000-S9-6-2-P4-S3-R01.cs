// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-6-2-P4-S3-R01")]
public sealed class REQ_QUIC_RFC9000_0535
{
    [Fact]
    [Requirement("RFC9000-S9-6-2-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerContinuesProcessingDelayedPacketsReceivedOnTheOldAddressAfterPreferredAddressValidationCompletes()
    {
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicConnectionTransitionResult handshakeResult = QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(
            runtime,
            observedAtTicks: 20);

        Assert.True(handshakeResult.StateChanged);

        QuicConnectionTransitionResult validationResult = QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 40);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(preferredPath));

        QuicConnectionTransitionResult delayedResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            runtime.CurrentPeerDestinationConnectionId.Span,
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x11, 0x22]),
            observedAtTicks: 50);

        Assert.True(delayedResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path));
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("RFC9000-S9-6-2-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DelayedOldAddressPacketDoesNotReopenTheOriginalAddressAsACandidatePath()
    {
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: 20);
        QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: 40);

        QuicConnectionTransitionResult delayedResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            runtime.CurrentPeerDestinationConnectionId.Span,
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x11]),
            observedAtTicks: 50);

        Assert.True(delayedResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path));
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect);
    }

    [Theory]
    [InlineData(1, new byte[] { 0x11 }, 20, 40, 50)]
    [InlineData(3, new byte[] { 0x21, 0x22 }, 25, 45, 67)]
    [InlineData(5, new byte[] { 0x31, 0x32, 0x33 }, 30, 55, 89)]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DelayedOldAddressPacketFuzz_RemainsProcessableWithoutReopeningOriginalPath(
        ulong streamId,
        byte[] streamPayload,
        long handshakeTicks,
        long validationTicks,
        long delayedTicks)
    {
        QuicConnectionPathIdentity preferredPath = QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath();

        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());

        QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: handshakeTicks);
        QuicS9P6P1PreferredAddressTestSupport.ValidatePreferredPath(
            runtime,
            preferredPath,
            observedAtTicks: validationTicks);

        QuicConnectionTransitionResult delayedResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path,
            runtime.CurrentPeerDestinationConnectionId.Span,
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId, streamPayload),
            observedAtTicks: delayedTicks);

        Assert.True(delayedResult.StateChanged);
        Assert.Equal(preferredPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path));
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect);
        Assert.DoesNotContain(delayedResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
    }
}
