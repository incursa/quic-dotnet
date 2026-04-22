using System.Reflection;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6-0001">Loss detection MUST be separate per packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6-0001")]
public sealed class REQ_QUIC_RFC9002_S6_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryProcessHandshakePacketPayload_InitialAckClearsOnlyInitialRecoveryState()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-182027795-client-chrome\
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-184853516-client-chrome\
        //   live docker logs client/server
        // The multiconnect client reached "sent HTTP/0.9 request line", but quic-go queued the
        // client's 1-RTT packets "for later decryption" and later timed out. The common cause was
        // that the client's lost Handshake packet stayed gated behind stale Initial recovery state
        // because Initial ACK frames were not clearing the Initial packet-number space.
        using QuicConnectionRuntime runtime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();

        ulong initialPacketNumber = Assert.Single(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial)
            .PacketNumber;

        SeedOutstandingRecoveryPacket(
            runtime,
            QuicPacketNumberSpace.Handshake,
            packetNumber: 41,
            sentAtMicros: 2,
            QuicTlsEncryptionLevel.Handshake);

        byte[] payload = BuildAckAndCryptoPayload(
            largestAcknowledged: initialPacketNumber,
            InteropEndpointHostTestSupport.CreateServerHelloTranscript());
        List<QuicConnectionEffect>? effects = null;

        Assert.True(TryProcessHandshakePacketPayload(
            runtime,
            payload,
            QuicTlsEncryptionLevel.Initial,
            nowTicks: 10,
            ref effects));
        Assert.True(runtime.TlsState.HandshakeKeysAvailable);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Initial
                && key.PacketNumber == initialPacketNumber);
        Assert.Contains(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                && key.PacketNumber == 41);
        Assert.True(TrySelectRecoveryTimer(
            runtime,
            nowTicks: 10,
            out _,
            out QuicPacketNumberSpace selectedPacketNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, selectedPacketNumberSpace);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDiscardPacketNumberSpace_RemovesOnlyTheDiscardedSpaceFromTheRuntimeLedger()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Initial,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Initial),
            PacketBytes: new byte[] { 0x01 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.Handshake,
            PacketNumber: 2,
            PayloadBytes: 1_200,
            SentAtMicros: 200,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(QuicTlsEncryptionLevel.Handshake),
            PacketBytes: new byte[] { 0x02 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 1_200,
            SentAtMicros: 300,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x03 }));
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 4,
            PayloadBytes: 1_200,
            SentAtMicros: 400,
            AckEliciting: true,
            PacketProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt,
            PacketBytes: new byte[] { 0x04 }));

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.DoesNotContain(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Initial);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake));
        Assert.DoesNotContain(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.Handshake);
        Assert.Equal(2, sendRuntime.SentPackets.Count);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.OneRtt);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && entry.Value.PacketProtectionLevel == QuicTlsEncryptionLevel.ZeroRtt);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDiscardPacketNumberSpace_IsNoOpForASpaceThatWasNeverTracked()
    {
        QuicConnectionSendRuntime sendRuntime = new();
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true,
            PacketBytes: new byte[] { 0x09 }));

        Assert.True(sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial));
        Assert.Single(sendRuntime.SentPackets);
        Assert.Contains(sendRuntime.SentPackets, entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData);
    }

    private delegate bool ProcessHandshakePacketPayloadDelegate(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects);

    private static bool TryProcessHandshakePacketPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        MethodInfo method = typeof(QuicConnectionRuntime).GetMethod(
            "TryProcessHandshakePacketPayload",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        ProcessHandshakePacketPayloadDelegate handler =
            method.CreateDelegate<ProcessHandshakePacketPayloadDelegate>();
        return handler(runtime, payload, encryptionLevel, nowTicks, ref effects);
    }

    private static byte[] BuildAckAndCryptoPayload(
        ulong largestAcknowledged,
        ReadOnlySpan<byte> cryptoBytes)
    {
        byte[] ackFrame = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = largestAcknowledged,
            AckDelay = 0,
            FirstAckRange = 0,
            AdditionalRanges = [],
        });
        byte[] cryptoFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, cryptoBytes.ToArray()));
        byte[] payload = new byte[ackFrame.Length + cryptoFrame.Length];
        ackFrame.CopyTo(payload, 0);
        cryptoFrame.CopyTo(payload, ackFrame.Length);
        return payload;
    }

    private static void SeedOutstandingRecoveryPacket(
        QuicConnectionRuntime runtime,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        ulong sentAtMicros,
        QuicTlsEncryptionLevel packetProtectionLevel)
    {
        byte[] packetBytes = [0x01, 0x02, 0x03, 0x04];
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            (ulong)packetBytes.Length,
            sentAtMicros,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: false,
            Retransmittable: true,
            CryptoMetadata: packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake
                ? new QuicConnectionCryptoSendMetadata(packetProtectionLevel)
                : null,
            PacketBytes: packetBytes,
            PacketProtectionLevel: packetProtectionLevel));
        GetRecoveryController(runtime).RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            isProbePacket: false,
            packetProtectionLevel);
    }

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
