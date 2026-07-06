// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0002")]
public sealed class REQ_QUIC_RFC9000_S19P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPaddingFrame_WritesBytesThatCanBeRepeatedToIncreasePacketSize()
    {
        Span<byte> packet = stackalloc byte[2];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet, out int firstBytesWritten));
        Assert.Equal(1, firstBytesWritten);
        Assert.Equal(0x00, packet[0]);

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet[firstBytesWritten..], out int secondBytesWritten));
        Assert.Equal(1, secondBytesWritten);
        Assert.Equal(2, firstBytesWritten + secondBytesWritten);
        Assert.Equal(0x00, packet[1]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatPaddingFrame_RejectsEmptyDestinations()
    {
        Assert.False(QuicFrameCodec.TryFormatPaddingFrame(Span<byte>.Empty, out _));
        Assert.False(QuicFrameCodec.TryParsePaddingFrame(ReadOnlySpan<byte>.Empty, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParsePaddingFrame_ConsumesOnlyTheSinglePaddingByteAtThePacketBoundary()
    {
        Span<byte> packet = stackalloc byte[1];

        Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet, out int bytesWritten));
        Assert.Equal(1, bytesWritten);

        Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet[..bytesWritten], out int bytesConsumed));
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryFormatPaddingFrame_FuzzWritesRepeatablePaddingBytes()
    {
        int[] packetSizes = [1, 2, 8, 32];

        foreach (int packetSize in packetSizes)
        {
            byte[] packet = new byte[packetSize];
            int index = 0;

            while (index < packet.Length)
            {
                Assert.True(QuicFrameCodec.TryFormatPaddingFrame(packet.AsSpan(index), out int bytesWritten));
                Assert.Equal(1, bytesWritten);
                Assert.True(QuicFrameCodec.TryParsePaddingFrame(packet.AsSpan(index, bytesWritten), out int bytesConsumed));
                Assert.Equal(bytesWritten, bytesConsumed);
                index += bytesWritten;
            }

            Assert.All(packet, static value => Assert.Equal(0x00, value));
        }
    }
}
