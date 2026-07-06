// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P2P5-0002">The endpoint MUST encode this acknowledgment delay in the ACK Delay field of an ACK frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
public sealed class REQ_QUIC_RFC9000_S13P2P5_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesTheAckDelayFieldAsTheSelectedDelay()
    {
        QuicAckFrame frame = CreateAckDelayFrame();

        Span<byte> expectedDelayEncoding = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        Assert.True(QuicVariableLengthInteger.TryFormat(frame.AckDelay, expectedDelayEncoding, out int expectedDelayBytes));

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, destination, out int bytesWritten));
        ReadOnlySpan<byte> formatted = destination[..bytesWritten];

        Assert.True(QuicVariableLengthInteger.TryParse(formatted, out ulong frameType, out int frameTypeBytes));
        Assert.Equal(0x02UL, frameType);

        Assert.True(QuicVariableLengthInteger.TryParse(formatted[frameTypeBytes..], out ulong largestAcknowledged, out int largestAcknowledgedBytes));
        Assert.Equal(frame.LargestAcknowledged, largestAcknowledged);

        int ackDelayOffset = frameTypeBytes + largestAcknowledgedBytes;
        Assert.True(QuicVariableLengthInteger.TryParse(formatted[ackDelayOffset..], out ulong ackDelay, out int ackDelayBytes));
        Assert.Equal(frame.AckDelay, ackDelay);
        Assert.Equal(expectedDelayBytes, ackDelayBytes);
        Assert.True(expectedDelayEncoding[..expectedDelayBytes].SequenceEqual(formatted.Slice(ackDelayOffset, ackDelayBytes)));

        Assert.True(QuicFrameCodec.TryParseAckFrame(formatted, out QuicAckFrame parsed, out int bytesConsumed));
        Assert.Equal(bytesWritten, bytesConsumed);
        Assert.Equal(frame.AckDelay, parsed.AckDelay);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsATruncatedAckDelayField()
    {
        QuicAckFrame frame = CreateAckDelayFrame();

        Span<byte> destination = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, destination, out int bytesWritten));
        ReadOnlySpan<byte> formatted = destination[..bytesWritten];

        Assert.True(QuicVariableLengthInteger.TryParse(formatted, out _, out int frameTypeBytes));
        Assert.True(QuicVariableLengthInteger.TryParse(formatted[frameTypeBytes..], out _, out int largestAcknowledgedBytes));

        int ackDelayOffset = frameTypeBytes + largestAcknowledgedBytes;
        Assert.True(QuicVariableLengthInteger.TryParse(formatted[ackDelayOffset..], out _, out int ackDelayBytes));
        Assert.True(ackDelayBytes > 1);

        Assert.False(QuicFrameCodec.TryParseAckFrame(formatted[..(ackDelayOffset + ackDelayBytes - 1)], out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P2P5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryFormatAckFrame_FuzzEncodesEachSelectedAckDelayField()
    {
        ulong[] ackDelays = [0, 1, 63, 64, 16_383, 16_384];

        foreach (ulong selectedDelay in ackDelays)
        {
            QuicAckFrame frame = CreateAckDelayFrame();
            frame.AckDelay = selectedDelay;

            byte[] destination = new byte[32];
            Assert.True(QuicFrameCodec.TryFormatAckFrame(frame, destination, out int bytesWritten));
            ReadOnlySpan<byte> formatted = destination[..bytesWritten];

            Assert.True(QuicVariableLengthInteger.TryParse(formatted, out _, out int frameTypeBytes));
            Assert.True(QuicVariableLengthInteger.TryParse(formatted[frameTypeBytes..], out _, out int largestAcknowledgedBytes));

            int ackDelayOffset = frameTypeBytes + largestAcknowledgedBytes;
            Assert.True(QuicVariableLengthInteger.TryParse(formatted[ackDelayOffset..], out ulong ackDelay, out _));
            Assert.Equal(selectedDelay, ackDelay);

            Assert.True(QuicFrameCodec.TryParseAckFrame(formatted, out QuicAckFrame parsed, out int bytesConsumed));
            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(selectedDelay, parsed.AckDelay);
        }
    }

    private static QuicAckFrame CreateAckDelayFrame()
    {
        return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0x02,
            AckDelay = 0x1234,
            FirstAckRange = 0x00,
        };
    }
}
