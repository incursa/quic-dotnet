// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicOutstandingSentStreamPacketIndexTests
{
    [Fact]
    public void AddAndRemove_TrackDistinctNonEmptyStreamFrames()
    {
        byte[] payload =
        [
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 1, []),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x11]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x12]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 2, [0x21]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 3, [0x31]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 4, [0x41]),
            ..QuicStreamTestData.BuildStreamFrame(0x0A, 5, [0x51]),
        ];
        QuicConnectionSentPacket packet = CreatePacket(1, payload);
        QuicOutstandingSentStreamPacketIndex index = new();

        index.Add(packet);

        Assert.Equal(1, index.GetCount(1));
        Assert.Equal(1, index.GetCount(2));
        Assert.Equal(1, index.GetCount(3));
        Assert.Equal(1, index.GetCount(4));
        Assert.Equal(1, index.GetCount(5));
        Assert.Equal(0, index.GetCount(6));

        index.Remove(packet);

        Assert.Equal(0, index.GetCount(1));
        Assert.Equal(0, index.GetCount(2));
        Assert.Equal(0, index.GetCount(3));
        Assert.Equal(0, index.GetCount(4));
        Assert.Equal(0, index.GetCount(5));
    }

    [Fact]
    public void RuntimePacketReplacement_ReplacesIndexedStreamOwnership()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(
            packetNumber: 7,
            QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x11])));

        runtime.TrackSentPacket(CreatePacket(
            packetNumber: 7,
            QuicStreamTestData.BuildStreamFrame(0x0A, 2, [0x22])));

        Assert.Equal(0, runtime.GetOutstandingSentStreamPacketCount(1));
        Assert.Equal(1, runtime.GetOutstandingSentStreamPacketCount(2));
        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.GetOutstandingSentStreamPacketCount(2));
    }

    [Fact]
    public void RuntimeRemovalPaths_ClearIndexedStreamOwnership()
    {
        AssertRemovalClearsIndex(runtime => Assert.True(runtime.TryDiscardPacketNumberSpace(
            QuicPacketNumberSpace.ApplicationData)));
        AssertRemovalClearsIndex(runtime => Assert.True(runtime.TryDiscardPacketProtectionLevel(
            QuicTlsEncryptionLevel.OneRtt)));
        AssertRemovalClearsIndex(runtime => Assert.True(runtime.TryDiscardOneRttKeyPhase(0)));
        AssertRemovalClearsIndex(runtime => Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true,
            scheduleRetransmission: false)));
    }

    [Fact]
    public void RuntimeIndex_IgnoresMetadataOnZeroLengthStreamFrames()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(
            packetNumber: 7,
            QuicStreamTestData.BuildStreamFrame(0x0B, 9, []),
            streamId: 9));

        Assert.Equal(0, runtime.GetOutstandingSentStreamPacketCount(9));
        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 7,
            handshakeConfirmed: true));
    }

    private static void AssertRemovalClearsIndex(Action<QuicConnectionSendRuntime> remove)
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(CreatePacket(
            packetNumber: 7,
            QuicStreamTestData.BuildStreamFrame(0x0A, 9, [0x99])));
        Assert.Equal(1, runtime.GetOutstandingSentStreamPacketCount(9));

        remove(runtime);

        Assert.Equal(0, runtime.GetOutstandingSentStreamPacketCount(9));
    }

    private static QuicConnectionSentPacket CreatePacket(
        ulong packetNumber,
        ReadOnlyMemory<byte> plaintextPayload,
        ulong? streamId = null)
        => new(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            PayloadBytes: (ulong)plaintextPayload.Length,
            SentAtMicros: packetNumber,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamId: streamId,
            PlaintextPayload: plaintextPayload,
            OneRttKeyPhase: 0);
}
