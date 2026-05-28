// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0011")]
public sealed class REQ_QUIC_RFC9000_S19P8_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_ParsesVariableLengthLengthField()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: 0x04,
            streamData: [0xAA, 0xBB, 0xCC]);

        Assert.True(frame.HasLength);
        Assert.Equal(3UL, frame.Length);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsTruncatedLengthVarint()
    {
        QuicS19P8StreamFrameTestSupport.AssertRejects([0x0A, 0x00, 0x40]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ParsesZeroLengthField()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: 0x04,
            streamData: []);

        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(0, frame.StreamDataLength);
    }
}
