// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S10-2-1-P4-S3-R01">An endpoint MAY retain packet protection keys for incoming packets to allow it to read and process a CONNECTION_CLOSE frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-2-1-P4-S3-R01")]
public sealed class REQ_QUIC_RFC9000_0579
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingRuntimeRetainsKeysAndProcessesPeerConnectionCloseFrames()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 10,
                closeMetadata),
            nowTicks: 10);

        QuicConnectionSendDatagramEffect[] closeSends = closeResult.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(closeSends);
        Assert.All(closeSends, effect => Assert.Equal(path, effect.PathIdentity));
        Assert.True(runtime.TlsState.OneRttKeysAvailable);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);

        QuicConnectionCloseFrame peerCloseFrame = new(
            QuicTransportErrorCode.ProtocolViolation,
            triggeringFrameType: 0x1c,
            []);
        byte[] peerCloseDatagram = QuicFrameTestData.BuildConnectionCloseFrame(peerCloseFrame);
        byte[] protectedPeerClosePacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x01],
            peerCloseDatagram,
            material,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                path,
                protectedPeerClosePacket),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosingRuntimeStillRepliesToProtectedPacketsThatDoNotCarryConnectionClose()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);
        QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 10,
                closeMetadata),
            nowTicks: 10);

        byte[] protectedPingPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x02],
            QuicFrameTestData.BuildPingFrame(),
            material,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                path,
                protectedPingPacket),
            nowTicks: 20);

        QuicConnectionSendDatagramEffect[] sends = result.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.NotEmpty(sends);
        Assert.All(sends, effect => Assert.Equal(path, effect.PathIdentity));
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClosingRuntimeUsesRetainedKeysForVariedProtectedCloseAndNonClosePackets()
    {
        for (int caseIndex = 0; caseIndex < 6; caseIndex++)
        {
            QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);
            QuicConnectionPathIdentity path = runtime.ActivePath!.Value.Identity;
            Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
            QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

            QuicConnectionCloseMetadata closeMetadata = new(
                TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x1c,
                ReasonPhrase: null);

            runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 10,
                    closeMetadata),
                nowTicks: 10);

            bool carriesPeerClose = caseIndex % 2 == 0;
            byte[] payload = carriesPeerClose
                ? QuicFrameTestData.BuildConnectionCloseFrame(new QuicConnectionCloseFrame(
                    QuicTransportErrorCode.ProtocolViolation,
                    triggeringFrameType: (ulong)(0x1c + caseIndex),
                    []))
                : QuicFrameTestData.BuildPingFrame();

            byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
                runtime.CurrentPeerDestinationConnectionId.Span,
                [0x00, 0x00, 0x00, (byte)(0x20 + caseIndex)],
                payload,
                material,
                declaredPacketNumberLength: 4);

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + caseIndex,
                    path,
                    protectedPacket),
                nowTicks: 20 + caseIndex);

            if (carriesPeerClose)
            {
                Assert.True(result.StateChanged);
                Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
                Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
                Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
            }
            else
            {
                QuicConnectionSendDatagramEffect[] sends = result.Effects
                    .OfType<QuicConnectionSendDatagramEffect>()
                    .ToArray();
                Assert.NotEmpty(sends);
                Assert.All(sends, effect => Assert.Equal(path, effect.PathIdentity));
                Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
                Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
            }
        }
    }
}
