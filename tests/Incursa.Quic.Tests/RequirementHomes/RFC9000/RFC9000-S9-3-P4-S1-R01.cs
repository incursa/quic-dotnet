// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-3-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S9P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnvalidatedPeerAddressCanReceiveAPathValidationChallengeBeforePromotion()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.100", RemotePort: 443);
        QuicConnectionPathIdentity unvalidatedPath = new("203.0.113.101", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unvalidatedPath,
                datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(unvalidatedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            unvalidatedPath,
            runtime: runtime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerHandshakeResponsesUseTheLatestUnvalidatedPeerAddressBeforePromotion()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.102", RemotePort: 443);
        QuicConnectionPathIdentity unvalidatedPath = new("203.0.113.102", RemotePort: 8443);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unvalidatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.ContainsKey(unvalidatedPath));
        Assert.Equal(unvalidatedPath, InvokeOutboundPathSelector(runtime, "TryGetInitialOutboundPath"));
        Assert.Equal(unvalidatedPath, InvokeOutboundPathSelector(runtime, "TryGetHandshakeOutboundPath"));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerHandshakeRetransmissionsUseTheLatestUnvalidatedPeerAddressBeforePromotion()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime serverRuntime = scenario.ServerRuntime;
        QuicConnectionPathIdentity unvalidatedPath = scenario.PathIdentity with
        {
            RemotePort = 8443,
        };

        QuicConnectionSentPacketKey initialPacketKey = GetFirstSentPacketKey(
            serverRuntime,
            QuicPacketNumberSpace.Initial);
        Assert.True(serverRuntime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            initialPacketKey.PacketNumber,
            handshakeConfirmed: false));

        Assert.True(serverRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unvalidatedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);

        Assert.True(serverRuntime.CandidatePaths.ContainsKey(unvalidatedPath));

        IReadOnlyList<QuicConnectionEffect> retransmissionEffects =
            InvokePendingRetransmissionFlush(
                serverRuntime,
                QuicPacketNumberSpace.Initial,
                nowTicks: 30,
                probePacket: true);

        QuicConnectionSendDatagramEffect retransmission = Assert.Single(
            retransmissionEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(unvalidatedPath, retransmission.PathIdentity);
        Assert.True(serverRuntime.ActivePath.HasValue);
        Assert.Equal(scenario.PathIdentity, serverRuntime.ActivePath!.Value.Identity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerHandshakeResponsesStayOnTheActivePathWhenNoUnvalidatedPeerAddressIsNewer()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.103", RemotePort: 443);
        using QuicConnectionRuntime runtime = CreateServerRuntimeWithActivePath(activePath);

        Assert.Equal(activePath, InvokeOutboundPathSelector(runtime, "TryGetInitialOutboundPath"));
        Assert.Equal(activePath, InvokeOutboundPathSelector(runtime, "TryGetHandshakeOutboundPath"));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerHandshakeRetransmissionsStayOnTheActivePathWhenNoUnvalidatedPeerAddressIsNewer()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();
        using QuicConnectionRuntime clientRuntime = scenario.ClientRuntime;
        using QuicConnectionRuntime serverRuntime = scenario.ServerRuntime;
        QuicConnectionSentPacketKey initialPacketKey = GetFirstSentPacketKey(
            serverRuntime,
            QuicPacketNumberSpace.Initial);

        Assert.True(serverRuntime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.Initial,
            initialPacketKey.PacketNumber,
            handshakeConfirmed: false));

        IReadOnlyList<QuicConnectionEffect> retransmissionEffects =
            InvokePendingRetransmissionFlush(
                serverRuntime,
                QuicPacketNumberSpace.Initial,
                nowTicks: 20,
                probePacket: true);

        QuicConnectionSendDatagramEffect retransmission = Assert.Single(
            retransmissionEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(scenario.PathIdentity, retransmission.PathIdentity);
    }

    private static QuicConnectionRuntime CreateServerRuntimeWithActivePath(QuicConnectionPathIdentity activePath)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10).StateChanged);

        return runtime;
    }

    private static QuicConnectionPathIdentity InvokeOutboundPathSelector(
        QuicConnectionRuntime runtime,
        string methodName)
    {
        return methodName switch
        {
            nameof(QuicConnectionRuntime.TryGetInitialOutboundPath) when runtime.TryGetInitialOutboundPath(out QuicConnectionPathIdentity path) => path,
            nameof(QuicConnectionRuntime.TryGetHandshakeOutboundPath) when runtime.TryGetHandshakeOutboundPath(out QuicConnectionPathIdentity path) => path,
            _ => throw new MissingMethodException(nameof(QuicConnectionRuntime), methodName),
        };
    }

    private static QuicConnectionSentPacketKey GetFirstSentPacketKey(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace)
    {
        foreach (QuicConnectionSentPacketKey key in runtime.SendRuntime.SentPackets.Keys)
        {
            if (key.PacketNumberSpace == packetNumberSpace)
            {
                return key;
            }
        }

        throw new InvalidOperationException($"No sent packet was tracked in {packetNumberSpace}.");
    }

    private static IReadOnlyList<QuicConnectionEffect> InvokePendingRetransmissionFlush(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket)
    {
        List<QuicConnectionEffect>? effects = null;
        Assert.True(runtime.TryFlushPendingRetransmissions(packetNumberSpace, nowTicks, probePacket, ref effects));
        return Assert.IsAssignableFrom<IReadOnlyList<QuicConnectionEffect>>(effects);
    }
}
