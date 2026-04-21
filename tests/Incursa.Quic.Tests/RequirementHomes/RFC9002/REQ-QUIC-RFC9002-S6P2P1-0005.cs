using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P1-0005">An endpoint MUST NOT set its PTO timer for the Application Data packet number space until the handshake is confirmed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P1-0005")]
public sealed class REQ_QUIC_RFC9002_S6P2P1_0005
{
    public static TheoryData<ApplicationDataPtoGateCase> ApplicationDataPtoGateCases => new()
    {
        new(false, false, 0),
        new(true, true, 2_500),
    };

    [Theory]
    [MemberData(nameof(ApplicationDataPtoGateCases))]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Property")]
    public void TryComputeProbeTimeoutMicros_GatesApplicationDataPtoOnHandshakeConfirmation(ApplicationDataPtoGateCase scenario)
    {
        Assert.Equal(scenario.ExpectedAccepted, QuicRecoveryTiming.TryComputeProbeTimeoutMicros(
            QuicPacketNumberSpace.ApplicationData,
            smoothedRttMicros: 1_000,
            rttVarMicros: 250,
            maxAckDelayMicros: 500,
            handshakeConfirmed: scenario.HandshakeConfirmed,
            out ulong probeTimeoutMicros,
            timerGranularityMicros: 1));

        Assert.Equal(scenario.ExpectedProbeTimeoutMicros, probeTimeoutMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ActiveClientRuntimeSkipsApplicationDataPtoUntilHandshakeDoneConfirmsTheHandshake()
    {
        // Regression from the managed client-role quic-go multiconnect run on 2026-04-21:
        // the runtime had peer transcript completion plus 1-RTT keys, but no preserved proof
        // that the client had received HANDSHAKE_DONE. Recovery still selected Application Data
        // PTO and emitted repeated 1-RTT probes while crypto-space repair lagged behind.
        // This proof seeds both spaces explicitly: Handshake stays eligible before confirmation,
        // and Application Data becomes eligible only after the remaining Handshake repair is gone
        // and HANDSHAKE_DONE confirms the handshake.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] handshakePacketBytes = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(
            packetNumberLength: 1,
            protectedPayload: QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA])));
        byte[] applicationPacketBytes = QuicFrameTestData.BuildPingFrame();

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 1,
            PayloadBytes: (ulong)handshakePacketBytes.Length,
            SentAtMicros: 0,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: false,
            Retransmittable: true,
            PacketBytes: handshakePacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.Handshake));
        GetRecoveryController(runtime).RecordPacketSent(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 1,
            sentAtMicros: 0,
            isAckElicitingPacket: true,
            isProbePacket: false,
            packetProtectionLevel: QuicTlsEncryptionLevel.Handshake);
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: (ulong)applicationPacketBytes.Length,
            SentAtMicros: 0,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: false,
            Retransmittable: true,
            PacketBytes: applicationPacketBytes,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));
        GetRecoveryController(runtime).RecordPacketSent(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            sentAtMicros: 0,
            isAckElicitingPacket: true,
            isProbePacket: false,
            packetProtectionLevel: QuicTlsEncryptionLevel.OneRtt);

        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.True(TrySelectRecoveryTimer(
            runtime,
            nowTicks: 0,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.Handshake,
            packetNumber: 1,
            handshakeConfirmed: false));
        Assert.True(GetRecoveryController(runtime).RecordAcknowledgment(
            QuicPacketNumberSpace.Handshake,
            largestAcknowledgedPacketNumber: 1,
            ackReceivedAtMicros: 10,
            newlyAcknowledgedAckElicitingPacketNumbers: [1UL],
            handshakeConfirmed: false));
        Assert.True(QuicPostHandshakeTicketTestSupport.ReceiveProtectedHandshakeDonePacket(runtime, observedAtTicks: 20).StateChanged);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.True(TrySelectRecoveryTimer(
            runtime,
            nowTicks: 0,
            out _,
            out selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, selectedPacketNumberSpace);
    }

    public sealed record ApplicationDataPtoGateCase(
        bool HandshakeConfirmed,
        bool ExpectedAccepted,
        ulong ExpectedProbeTimeoutMicros);

    private static bool TrySelectRecoveryTimer(
        QuicConnectionRuntime runtime,
        long nowTicks,
        out ulong selectedRecoveryTimerMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TrySelectRecoveryTimer",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        object?[] arguments =
        [
            nowTicks,
            default(ulong),
            default(QuicPacketNumberSpace),
        ];

        bool selected = (bool)method.Invoke(runtime, arguments)!;
        selectedRecoveryTimerMicros = (ulong)arguments[1]!;
        selectedPacketNumberSpace = (QuicPacketNumberSpace)arguments[2]!;
        return selected;
    }

    private static QuicRecoveryController GetRecoveryController(QuicConnectionRuntime runtime)
    {
        FieldInfo field = typeof(QuicConnectionRuntime).GetField(
            "recoveryController",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        return (QuicRecoveryController)field.GetValue(runtime)!;
    }
}
