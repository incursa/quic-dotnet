// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
public sealed class REQ_QUIC_RFC9000_S19P3P2_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatAckFrame_EncodesEct0CountAsVariableLengthInteger()
    {
        byte[] encoded = QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
            QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                ect0Count: 0x40,
                ect1Count: 1,
                ecnCeCount: 2));

        (ulong value, int bytesConsumed) = QuicAckEcnFrameCodecTestSupport.ParseEcnCountField(encoded, fieldIndex: 0);

        Assert.Equal(0x40UL, value);
        Assert.Equal(2, bytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseAckFrame_RejectsMissingEct0CountField()
    {
        QuicS19P3AckFrameTestSupport.AssertRejects(
            QuicS19P3AckFrameTestSupport.BuildPayload(
                [0x03],
                QuicS19P3AckFrameTestSupport.Varint(4),
                QuicS19P3AckFrameTestSupport.Varint(1),
                QuicS19P3AckFrameTestSupport.Varint(0),
                QuicS19P3AckFrameTestSupport.Varint(0)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P3P2-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseAckFrame_PreservesZeroEct0CountField()
    {
        QuicAckFrame parsed = QuicAckEcnFrameCodecTestSupport.ParseAckFrame(
            QuicAckEcnFrameCodecTestSupport.FormatAckFrame(
                QuicAckEcnFrameCodecTestSupport.CreateAckEcnFrame(
                    ect0Count: 0,
                    ect1Count: 1,
                    ecnCeCount: 2)));

        Assert.Equal(0UL, parsed.EcnCounts!.Value.Ect0Count);
    }
}
