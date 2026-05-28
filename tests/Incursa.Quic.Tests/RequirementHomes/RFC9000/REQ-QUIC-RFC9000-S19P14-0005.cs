// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
public sealed class REQ_QUIC_RFC9000_S19P14_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_ParsesTheMaximumStreamsVarint()
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(maximumStreams: 0x1234);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: true,
            expectedMaximumStreams: 0x1234);
    }

    [Theory]
    [InlineData(0x3FUL, 1)]
    [InlineData(0x40UL, 2)]
    [InlineData(0x3FFFUL, 2)]
    [InlineData(0x4000UL, 4)]
    [InlineData(0x3FFF_FFFFUL, 4)]
    [InlineData(0x4000_0000UL, 8)]
    [InlineData(QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit, 8)]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_AcceptsMaximumStreamsVarintLengthsWithinTheStreamLimit(
        ulong maximumStreams,
        int expectedMaximumStreamsFieldLength)
    {
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(maximumStreams: maximumStreams);

        Assert.True(QuicFrameCodec.TryParseStreamsBlockedFrame(
            encoded,
            out QuicStreamsBlockedFrame frame,
            out int bytesConsumed));

        Assert.True(frame.IsBidirectional);
        Assert.Equal(maximumStreams, frame.MaximumStreams);
        Assert.Equal(1 + expectedMaximumStreamsFieldLength, bytesConsumed);
        QuicS19P14StreamsBlockedFrameTestSupport.AssertFormats(frame, encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsTruncatedMaximumStreamsVarints()
    {
        byte[][] truncatedMaximumStreamsFields =
        [
            [0x40],
            [0x80, 0x00, 0x00],
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        foreach (byte[] encodedMaximumStreams in truncatedMaximumStreamsFields)
        {
            byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrameWithEncodedMaximumStreams(
                isBidirectional: true,
                encodedMaximumStreams);

            QuicS19P14StreamsBlockedFrameTestSupport.AssertRejects(encoded);
        }
    }
}
