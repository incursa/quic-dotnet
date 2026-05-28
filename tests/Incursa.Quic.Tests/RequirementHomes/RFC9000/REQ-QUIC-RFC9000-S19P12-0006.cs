// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
public sealed class REQ_QUIC_RFC9000_S19P12_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseDataBlockedFrame_PreservesTheBlockingConnectionLimit()
    {
        ulong connectionLevelLimit = 0x1234_5678UL;
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrame(connectionLevelLimit);

        QuicS19P12DataBlockedFrameTestSupport.AssertParses(encoded, connectionLevelLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseDataBlockedFrame_PreservesTheMaximumVarintConnectionLimit()
    {
        ulong connectionLevelLimit = QuicVariableLengthInteger.MaxValue;
        byte[] encoded = QuicS19P12DataBlockedFrameTestSupport.BuildDataBlockedFrame(connectionLevelLimit);

        QuicS19P12DataBlockedFrameTestSupport.AssertParses(encoded, connectionLevelLimit);
        Assert.Equal(1 + QuicVariableLengthInteger.MaxEncodedLength, encoded.Length);
        QuicS19P12DataBlockedFrameTestSupport.AssertFormats(new QuicDataBlockedFrame(connectionLevelLimit), encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P12-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatDataBlockedFrame_RejectsConnectionLimitsAboveTheVarintRange()
    {
        QuicDataBlockedFrame frame = new(QuicVariableLengthInteger.MaxValue + 1);
        Span<byte> destination = stackalloc byte[16];

        Assert.False(QuicFrameCodec.TryFormatDataBlockedFrame(frame, destination, out _));
    }
}
