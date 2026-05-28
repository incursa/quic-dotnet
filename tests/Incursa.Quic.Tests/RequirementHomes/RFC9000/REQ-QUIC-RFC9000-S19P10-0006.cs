// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0006")]
public sealed class REQ_QUIC_RFC9000_S19P10_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_ParsesStreamIdAsVarint()
    {
        ulong streamId = 0x1234;
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId, maximumStreamData: 16);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: streamId, expectedMaximumStreamData: 16);
        QuicS19P10MaxStreamDataFrameTestSupport.AssertFormats(new QuicMaxStreamDataFrame(streamId, 16), encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamDataFrame_RejectsTruncatedStreamIdVarint()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrameWithEncodedStreamId([0x40]);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_PreservesMaximumVarintStreamId()
    {
        ulong streamId = QuicVariableLengthInteger.MaxValue;
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId, maximumStreamData: 16);

        QuicS19P10MaxStreamDataFrameTestSupport.AssertParses(encoded, expectedStreamId: streamId, expectedMaximumStreamData: 16);
        QuicS19P10MaxStreamDataFrameTestSupport.AssertFormats(new QuicMaxStreamDataFrame(streamId, 16), encoded);
    }
}
