namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9287-S3-0003")]
public sealed class REQ_QUIC_RFC9287_S3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NegotiatedGreaseQuicBitAcceptsClearedFixedBitPacketsAfterTransportParameters()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x01, 0x02, 0x03];

        bool buildSucceeded = senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit,
            out ulong packetNumber,
            out byte[] protectedPacket);
        Assert.True(
            buildSucceeded,
            $"dest={senderCoordinator.DestinationConnectionId.Length}, source={senderCoordinator.SourceConnectionId.Length}, openMaterial={senderRuntime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue}, protectMaterial={senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue}, peerGrease={senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit}");

        Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.Equal(senderRuntime.TlsState.CurrentOneRttKeyPhaseBit, keyPhase);
        Assert.Equal(0, openedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.True(applicationPayload.SequenceEqual(openedPacket.AsSpan(payloadOffset, applicationPayload.Length)));
        Assert.True(openedPacket.AsSpan(
            payloadOffset + applicationPayload.Length,
            payloadLength - applicationPayload.Length).SequenceEqual(new byte[payloadLength - applicationPayload.Length]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StrictOpenRejectsFixedBitZeroPacketsWithoutNegotiation()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x04, 0x05, 0x06];

        Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: true,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.False(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: false,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NegotiatedGreaseQuicBitAcceptsClearedFixedBitPacketsAtTheShortestPayload()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x01];

        Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: senderRuntime.TlsState.PeerTransportParameters.GreaseQuicBit,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(0, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: true,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));

        Assert.Equal(senderRuntime.TlsState.CurrentOneRttKeyPhaseBit, keyPhase);
        Assert.True(applicationPayload.SequenceEqual(openedPacket.AsSpan(payloadOffset, applicationPayload.Length)));
        Assert.True(openedPacket.AsSpan(
            payloadOffset + applicationPayload.Length,
            payloadLength - applicationPayload.Length).SequenceEqual(new byte[payloadLength - applicationPayload.Length]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NegotiatedGreaseQuicBit_AcceptsClearedFixedBitPacketsAcrossRepresentativePayloads()
    {
        QuicGreaseQuicBitFuzzSupport.FuzzGreasedPacketAcceptancePolicy();
    }
}
