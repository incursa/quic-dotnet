// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P10-0008")]
public sealed class REQ_QUIC_RFC9000_S19P10_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseMaxStreamDataFrame_ConsumesTypeStreamIdAndMaximumStreamDataFields()
    {
        byte[] encoded = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 0x06, maximumStreamData: 0x1234);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(encoded, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(0x06UL, frame.StreamId);
        Assert.Equal(0x1234UL, frame.MaximumStreamData);
        Assert.Equal(encoded.Length, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseMaxStreamDataFrame_RejectsMissingMaximumStreamDataField()
    {
        byte[] encoded = [
            QuicS19P10MaxStreamDataFrameTestSupport.MaxStreamDataFrameType,
            .. QuicS19P10MaxStreamDataFrameTestSupport.EncodeVarint(1),
        ];

        QuicS19P10MaxStreamDataFrameTestSupport.AssertRejects(encoded);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamDataFrame_StopsBeforeTheNextFrameInThePacketPayload()
    {
        byte[] frameOnly = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrame(streamId: 1, maximumStreamData: 16);
        byte[] packetPayload = QuicS19P10MaxStreamDataFrameTestSupport.BuildMaxStreamDataFrameWithTrailingFrame(
            streamId: 1,
            maximumStreamData: 16,
            trailingFrameType: 0x01);

        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packetPayload, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(16UL, frame.MaximumStreamData);
        Assert.Equal(frameOnly.Length, bytesConsumed);
        Assert.Equal(0x01, packetPayload[bytesConsumed]);
    }
}
