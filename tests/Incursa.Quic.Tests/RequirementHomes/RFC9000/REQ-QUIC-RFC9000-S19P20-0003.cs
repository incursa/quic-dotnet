// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0003")]
public sealed class REQ_QUIC_RFC9000_S19P20_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatHandshakeDoneFrame_WritesTheSingleByteVarintTypeValue()
    {
        Span<byte> destination = stackalloc byte[8];

        Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(default, destination, out int bytesWritten));

        Assert.Equal(1, bytesWritten);
        Assert.Equal(0x1E, destination[0]);
    }

    [Theory]
    [InlineData(0x1D)]
    [InlineData(0x1F)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseHandshakeDoneFrame_RejectsOtherSingleByteVarintTypeValues(byte frameType)
    {
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([frameType], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseHandshakeDoneFrame_RejectsNonMinimalVarintEncodingOfTheTypeValue()
    {
        Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([0x40, 0x1E], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseHandshakeDoneFrame_ConsumesOnlyTheSingleTypeByteWhenAnotherFrameFollows()
    {
        byte[] packetPayload =
        [
            .. QuicFrameTestData.BuildHandshakeDoneFrame(),
            .. QuicFrameTestData.BuildPingFrame(),
        ];

        Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(packetPayload, out _, out int bytesConsumed));

        Assert.Equal(1, bytesConsumed);
        Assert.True(QuicFrameCodec.TryParsePingFrame(packetPayload[bytesConsumed..], out int pingBytesConsumed));
        Assert.Equal(1, pingBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void Fuzz_HandshakeDoneFrame_RoundTripsAndRejectsTruncation()
    {
        Random random = new(0x5160_2080);
        Span<byte> destination = stackalloc byte[8];

        for (int iteration = 0; iteration < 128; iteration++)
        {
            byte[] packet = [0x1E];
            byte[] trailingBytes = new byte[random.Next(0, 8)];
            random.NextBytes(trailingBytes);

            if (trailingBytes.Length != 0)
            {
                packet = packet.Concat(trailingBytes).ToArray();
            }

            Assert.True(QuicFrameCodec.TryParseHandshakeDoneFrame(packet, out QuicHandshakeDoneFrame parsed, out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);

            Assert.True(QuicFrameCodec.TryFormatHandshakeDoneFrame(parsed, destination, out int bytesWritten));
            Assert.Equal(1, bytesWritten);
            Assert.True(destination[..bytesWritten].SequenceEqual(packet[..1]));

            Assert.False(QuicFrameCodec.TryParseHandshakeDoneFrame([], out _, out _));
        }
    }
}
