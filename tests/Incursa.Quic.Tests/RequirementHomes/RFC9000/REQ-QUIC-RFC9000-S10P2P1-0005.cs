// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P2P1-0005">To avoid being used for an amplification attack, such endpoints MUST limit the cumulative size of packets it sends to three times the cumulative size of the packets that are received and attributed to the connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P2P1-0005")]
public sealed class REQ_QUIC_RFC9000_S10P2P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingRuntimeRepliesToAttributedPacketsAndStaysWithinTheThreeToOneBudget()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.10", RemotePort: 443);
        const int receivedPayloadBytes = 8_000;

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[receivedPayloadBytes]),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.False(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.False(runtime.HasValidatedPath);
        ulong sentBeforeClose = runtime.ActivePath.Value.AmplificationState.SentPayloadBytes;
        Assert.Equal((ulong)receivedPayloadBytes, runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "closing");

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(closeResult.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        Assert.True(runtime.ActivePath.Value.AmplificationState.SentPayloadBytes > sentBeforeClose);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                new byte[receivedPayloadBytes]),
            nowTicks: 2);

        Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));
        Assert.Equal(path, runtime.ActivePath!.Value.Identity);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.False(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.False(runtime.HasValidatedPath);
        Assert.Equal((ulong)(receivedPayloadBytes * 2), runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
        Assert.True(runtime.ActivePath.Value.AmplificationState.SentPayloadBytes > sentBeforeClose);
        Assert.True(runtime.ActivePath.Value.AmplificationState.SentPayloadBytes <= runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes * 3UL);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosingRuntimeSuppressesRepliesWhenTheClosePacketWouldExceedTheReplyBudget()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        QuicConnectionPathIdentity path = new("203.0.113.10", RemotePort: 443);
        const int receivedPayloadBytes = 1;

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                path,
                new byte[receivedPayloadBytes]),
            nowTicks: 0).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.False(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.False(runtime.HasValidatedPath);
        ulong sentBeforeClose = runtime.ActivePath.Value.AmplificationState.SentPayloadBytes;
        Assert.Equal((ulong)receivedPayloadBytes, runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: "closing");

        QuicConnectionTransitionResult closeResult = runtime.Transition(
            new QuicConnectionLocalCloseRequestedEvent(
                ObservedAtTicks: 1,
                closeMetadata),
            nowTicks: 1);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.DoesNotContain(closeResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Equal(sentBeforeClose, runtime.ActivePath.Value.AmplificationState.SentPayloadBytes);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                path,
                new byte[receivedPayloadBytes]),
            nowTicks: 2);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.False(runtime.ActivePath.Value.IsValidated);
        Assert.False(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.False(runtime.HasValidatedPath);
        Assert.Equal((ulong)(receivedPayloadBytes * 2), runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
        Assert.Equal(sentBeforeClose, runtime.ActivePath.Value.AmplificationState.SentPayloadBytes);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        byte[] localHandshakePrivateKey = new byte[32];
        localHandshakePrivateKey[^1] = 0x11;

        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server,
            localHandshakePrivateKey: localHandshakePrivateKey);

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId(QuicS17P2P2TestSupport.InitialDestinationConnectionId));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId(QuicS17P2P2TestSupport.InitialSourceConnectionId));

        return runtime;
    }
}
