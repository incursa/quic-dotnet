// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P6_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P6-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void UnexpectedServerAddressFuzz_DiscardsUnlessClientInitiatedPreferredAddressMigration()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity originalPath = iteration % 2 == 0
                ? QuicS9P6P1PreferredAddressTestSupport.OriginalIpv4Path
                : QuicS9P6P1PreferredAddressTestSupport.OriginalIpv6Path;
            QuicConnectionPathIdentity unexpectedServerPath = new(
                RemoteAddress: iteration % 2 == 0
                    ? $"203.0.113.{90 + iteration}"
                    : $"2001:db8:2::{90 + iteration}",
                RemotePort: (ushort)(9443 + iteration));

            AssertUnexpectedServerAddressPacketDiscarded(
                originalPath,
                unexpectedServerPath,
                packetNumber: (ushort)(0x100 + iteration),
                observedAtTicks: 20 + iteration);

            AssertPreferredAddressMigrationPacketRetained(
                originalPath,
                useIpv6PreferredAddress: iteration % 2 != 0,
                packetNumber: (ushort)(0x200 + iteration),
                observedAtTicks: 40 + iteration);
        }
    }

    private static void AssertUnexpectedServerAddressPacketDiscarded(
        QuicConnectionPathIdentity originalPath,
        QuicConnectionPathIdentity unexpectedServerPath,
        ushort packetNumber,
        long observedAtTicks)
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(originalPath);
        byte[] protectedPacket = CreateProtectedStreamPacket(runtime, packetNumber, streamByte: (byte)(packetNumber & 0xFF));

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                unexpectedServerPath,
                protectedPacket),
            nowTicks: observedAtTicks);

        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(unexpectedServerPath));
        Assert.False(runtime.RecentlyValidatedPaths.ContainsKey(unexpectedServerPath));
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == unexpectedServerPath);
    }

    private static void AssertPreferredAddressMigrationPacketRetained(
        QuicConnectionPathIdentity originalPath,
        bool useIpv6PreferredAddress,
        ushort packetNumber,
        long observedAtTicks)
    {
        using QuicConnectionRuntime runtime = QuicS9P6P1PreferredAddressTestSupport.CreateClientRuntime(
            originalPath,
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredAddress());
        QuicConnectionPathIdentity preferredPath =
            QuicS9P6P1PreferredAddressTestSupport.CreatePreferredPath(useIpv6PreferredAddress);

        QuicConnectionTransitionResult handshakeDoneResult =
            QuicS9P6P1PreferredAddressTestSupport.ConfirmHandshake(runtime, observedAtTicks: observedAtTicks - 10);
        Assert.Contains(handshakeDoneResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == preferredPath);

        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePathBefore));

        byte[] protectedPacket = CreateProtectedStreamPacket(runtime, packetNumber, streamByte: (byte)(packetNumber & 0xFF));
        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                preferredPath,
                protectedPacket),
            nowTicks: observedAtTicks);

        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(preferredPath, out QuicConnectionCandidatePathRecord candidatePathAfter));
        Assert.True(candidatePathAfter.LastActivityTicks > candidatePathBefore.LastActivityTicks);
        Assert.False(candidatePathAfter.Validation.IsAbandoned);
        Assert.True(result.StateChanged);
    }

    private static byte[] CreateProtectedStreamPacket(
        QuicConnectionRuntime runtime,
        ushort packetNumber,
        byte streamByte)
    {
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        byte[] packetNumberBytes =
        [
            (byte)(packetNumber >> 8),
            (byte)packetNumber,
        ];

        return QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes,
            QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [streamByte]),
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: packetNumberBytes.Length);
    }
}
