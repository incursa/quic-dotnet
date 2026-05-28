// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEcnCeCountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 1,
                ect1Count: 2,
                ecnCeCount: 0x4000));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 2);

        Assert.Equal(0x4000UL, value);
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsMissingEcnCeCountField()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x03],
                QuicS19P3AckFrameTestSupport.Varint(4),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(2)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_PreservesZeroEcnCeCountField()
    {
        QuicAckFrame parsed = QuicAckEcnFrameCodecTestSupport.ParseAckFrame(
            QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
                QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                    ect0Count: 1,
                    ect1Count: 2,
                    ecnCeCount: 0)));

        Assert.Equal(0UL, parsed.EcnCounts!.Value.EcnCeCount);
    }
}
