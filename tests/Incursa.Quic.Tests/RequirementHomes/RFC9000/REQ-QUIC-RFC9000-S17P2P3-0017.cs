using System.Diagnostics;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P3-0017")]
public sealed class REQ_QUIC_RFC9000_S17P2P3_0017
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void BootstrapEmitsTheInitialPacketBeforeTheZeroRttPacketWhenEarlyDataIsReady()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.True(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.True(result.StateChanged);
        Assert.True(clientRuntime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.ZeroRtt,
            out _));

        QuicConnectionSendDatagramEffect[] initialEffects = QuicS17P2P3TestSupport.GetInitialSendEffects(result.Effects);
        QuicConnectionSendDatagramEffect[] zeroRttEffects = QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects);
        Assert.Single(initialEffects);
        Assert.Single(zeroRttEffects);
        Assert.Equal(QuicS17P2P3TestSupport.BootstrapPath, initialEffects[0].PathIdentity);
        Assert.Equal(QuicS17P2P3TestSupport.BootstrapPath, zeroRttEffects[0].PathIdentity);

        int initialIndex = Array.FindIndex(
            result.Effects,
            effect => effect is QuicConnectionSendDatagramEffect sendEffect
                && QuicS17P2P3TestSupport.IsInitialPacket(sendEffect.Datagram.Span));
        int zeroRttIndex = Array.FindIndex(
            result.Effects,
            effect => effect is QuicConnectionSendDatagramEffect sendEffect
                && QuicS17P2P3TestSupport.IsZeroRttPacket(sendEffect.Datagram.Span));

        Assert.True(initialIndex >= 0);
        Assert.True(zeroRttIndex >= 0);
        Assert.True(initialIndex < zeroRttIndex);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BootstrapWithoutEarlyDataReadinessEmitsOnlyTheInitialPacket()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime();
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();

        Assert.False(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
        Assert.False(clientRuntime.HasDormantEarlyDataAttemptReadiness);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: Stopwatch.Frequency,
                LocalTransportParameters: localTransportParameters),
            nowTicks: Stopwatch.Frequency);

        Assert.Single(QuicS17P2P3TestSupport.GetInitialSendEffects(result.Effects));
        Assert.Empty(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzBootstrapZeroRttOrdering_BoundarySamplingKeepsInitialBeforeZeroRtt()
    {
        Random random = new(0x0017);

        for (int iteration = 0; iteration < 128; iteration++)
        {
            bool includeEarlyData = random.Next(2) == 0;
            uint? ticketMaxEarlyDataSize = includeEarlyData
                ? (uint)random.Next(1, 1 << 16)
                : null;

            QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
                QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize);
            QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
            long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + Stopwatch.Frequency + iteration;

            using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(
                detachedResumptionTicketSnapshot);

            Assert.Equal(includeEarlyData, clientRuntime.HasDormantEarlyDataAttemptReadiness);

            QuicConnectionTransitionResult result = clientRuntime.Transition(
                new QuicConnectionHandshakeBootstrapRequestedEvent(
                    ObservedAtTicks: nowTicks,
                    LocalTransportParameters: localTransportParameters),
                nowTicks);

            QuicConnectionSendDatagramEffect[] initialEffects = QuicS17P2P3TestSupport.GetInitialSendEffects(result.Effects);
            QuicConnectionSendDatagramEffect[] zeroRttEffects = QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects);
            Assert.Single(initialEffects);

            int initialIndex = Array.FindIndex(
                result.Effects,
                effect => effect is QuicConnectionSendDatagramEffect sendEffect
                    && QuicS17P2P3TestSupport.IsInitialPacket(sendEffect.Datagram.Span));
            int zeroRttIndex = Array.FindIndex(
                result.Effects,
                effect => effect is QuicConnectionSendDatagramEffect sendEffect
                    && QuicS17P2P3TestSupport.IsZeroRttPacket(sendEffect.Datagram.Span));

            Assert.True(initialIndex >= 0);

            if (includeEarlyData)
            {
                Assert.True(clientRuntime.HasDormantDetachedResumptionTicketSnapshot);
                Assert.Single(zeroRttEffects);
                Assert.True(zeroRttIndex >= 0);
                Assert.True(initialIndex < zeroRttIndex);
            }
            else
            {
                Assert.Empty(zeroRttEffects);
                Assert.Equal(-1, zeroRttIndex);
            }
        }
    }
}
