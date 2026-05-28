// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0158")]
public sealed class REQ_QUIC_RFC9000_0158
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0158")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAndParseCryptoFrame_AllowsOffsetsThatDoNotFollowStreamFlowControl()
    {
        QuicCryptoFrame frame = new(QuicVariableLengthInteger.MaxValue - 1, [0xAA]);
        Span<byte> destination = stackalloc byte[16];

        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(frame, destination, out int bytesWritten));
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(destination[..bytesWritten], out QuicCryptoFrame parsedFrame, out int bytesConsumed));

        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.Offset, parsedFrame.Offset);
        Assert.True(frame.CryptoData.SequenceEqual(parsedFrame.CryptoData));
    }
}
