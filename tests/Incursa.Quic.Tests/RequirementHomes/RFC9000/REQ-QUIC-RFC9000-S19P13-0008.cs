// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
public sealed class REQ_QUIC_RFC9000_S19P13_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_PreservesTheBlockedStreamOffset()
    {
        ulong blockedOffset = 0x1234_5678UL;
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(maximumStreamData: blockedOffset);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, expectedStreamId: 4, expectedMaximumStreamData: blockedOffset);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamDataBlockedFrame_PreservesTheMaximumVarintBlockedStreamOffset()
    {
        ulong blockedOffset = QuicVariableLengthInteger.MaxValue;
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(maximumStreamData: blockedOffset);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, expectedStreamId: 4, expectedMaximumStreamData: blockedOffset);
        Assert.Equal(1 + 1 + QuicVariableLengthInteger.MaxEncodedLength, encoded.Length);
        QuicS19P13StreamDataBlockedFrameTestSupport.AssertFormats(new QuicStreamDataBlockedFrame(4, blockedOffset), encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStreamDataBlockedFrame_RejectsBlockedOffsetsAboveTheVarintRange()
    {
        QuicStreamDataBlockedFrame frame = new(streamId: 4, maximumStreamData: QuicVariableLengthInteger.MaxValue + 1);
        Span<byte> destination = stackalloc byte[24];

        Assert.False(QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, destination, out _));
    }
}
