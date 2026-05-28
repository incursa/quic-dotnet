// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0003")]
public sealed class REQ_QUIC_RFC9000_S19P8_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_LenBitIndicatesLengthFieldIsPresent()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0A,
            streamId: 0x04,
            streamData: [0xAA, 0xBB]);

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.ParsePacket(packet);

        Assert.True(frame.HasLength);
        Assert.Equal(2UL, frame.Length);
        Assert.Equal(packet.Length, frame.ConsumedLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsMissingLengthWhenLenBitIsSet()
    {
        QuicS19P8StreamFrameTestSupport.AssertRejects([0x0A, 0x00]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_AcceptsZeroLengthWhenLenBitIsSet()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0A,
            streamId: 0x04,
            streamData: []);

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.ParsePacket(packet);

        Assert.True(frame.HasLength);
        Assert.Equal(0UL, frame.Length);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.StreamData.IsEmpty);
    }
}
