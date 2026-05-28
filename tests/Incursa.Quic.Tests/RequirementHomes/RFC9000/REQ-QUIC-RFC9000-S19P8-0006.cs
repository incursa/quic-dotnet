// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0006")]
public sealed class REQ_QUIC_RFC9000_S19P8_0006
{
    [Theory]
    [InlineData((byte)0x09)]
    [InlineData((byte)0x0B)]
    [InlineData((byte)0x0D)]
    [InlineData((byte)0x0F)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_FinBitMarksEndOfStream(byte frameType)
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType,
            streamId: 0x04,
            streamData: [0xAA],
            offset: (frameType & QuicStreamFrameBits.OffsetBitMask) != 0 ? 1UL : 0UL);

        Assert.True(frame.IsFin);
        Assert.True((frame.FrameType & QuicStreamFrameBits.FinBitMask) != 0);
    }
}
