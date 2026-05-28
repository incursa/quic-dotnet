// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9287-S3-0004")]
public sealed class REQ_QUIC_RFC9287_S3_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NegotiatedGreaseQuicBitClearsFixedBitOnOutboundPackets()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x07, 0x08, 0x09];

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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StrictOutboundBuildPreservesFixedBitWithoutGreaseNegotiation()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = false;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = false;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x0A, 0x0B, 0x0C];

        Assert.True(senderCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            senderRuntime.TlsState.CurrentOneRttKeyPhaseBit,
            spinBit: false,
            greaseQuicBit: false,
            out ulong packetNumber,
            out byte[] protectedPacket));

        Assert.Equal(QuicPacketHeaderBits.FixedBitMask, protectedPacket[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.True(senderCoordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            senderRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            packetNumber,
            allowClearedFixedBit: false,
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
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RuntimeOutboundSendPreservesFixedBitWhenOnlyLocalEndpointAdvertisedGreaseQuicBit()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = false;

        QuicConnectionSendDatagramEffect sendEffect =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(senderRuntime);

        Assert.Equal(
            QuicPacketHeaderBits.FixedBitMask,
            sendEffect.Datagram.Span[0] & QuicPacketHeaderBits.FixedBitMask);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NegotiatedGreaseQuicBitClearsFixedBitOnOutboundPacketsAtTheShortestPayload()
    {
        using QuicConnectionRuntime senderRuntime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        senderRuntime.TlsState.LocalTransportParameters!.GreaseQuicBit = true;
        senderRuntime.TlsState.PeerTransportParameters!.GreaseQuicBit = true;

        QuicHandshakeFlowCoordinator senderCoordinator = senderRuntime.HandshakeFlowCoordinator;
        ReadOnlySpan<byte> applicationPayload = [0x0D];

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
    public void Fuzz_NegotiatedGreaseQuicBit_ClearsFixedBitAcrossRepresentativePayloads()
    {
        QuicGreaseQuicBitFuzzSupport.FuzzGreasedPacketTransmissionPolicy();
    }
}
