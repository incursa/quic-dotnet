// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S4-0001")]
public sealed class REQ_QUIC_RFC9221_S4_0001_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_AcceptsOnlyFrameTypes30And31()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30, 0xAA }, out QuicDatagramFrame withoutLength, out _));
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x01, 0xBB }, out QuicDatagramFrame withLength, out _));
        Assert.Equal(0x30, withoutLength.FrameType);
        Assert.Equal(0x31, withLength.FrameType);
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x32, 0x00 }, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDatagramFrameTypes_RoundTripOnlyDatagramTypes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

[Requirement("REQ-QUIC-RFC9221-S4-0002")]
public sealed class REQ_QUIC_RFC9221_S4_0002_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramLenBit_ControlsWhetherLengthFieldIsPresent()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30, 0xAA, 0xBB }, out QuicDatagramFrame withoutLength, out int withoutLengthBytes));
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x01, 0xCC, 0xDD }, out QuicDatagramFrame withLength, out int withLengthBytes));

        Assert.Equal([0xAA, 0xBB], withoutLength.DatagramData.ToArray());
        Assert.Equal(3, withoutLengthBytes);
        Assert.Equal([0xCC], withLength.DatagramData.ToArray());
        Assert.Equal(3, withLengthBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramLenBitWithoutLengthConsumesPacketRemainder()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30 }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal(0, frame.DatagramData.Length);
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDatagramLenBit_RoundTripsRepresentativeShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

[Requirement("REQ-QUIC-RFC9221-S4-0003")]
public sealed class REQ_QUIC_RFC9221_S4_0003_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramWithoutLength_ConsumesRemainingPacketPayload()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30, 0x10, 0x11, 0x12 }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal([0x10, 0x11, 0x12], frame.DatagramData.ToArray());
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramWithoutLength_AllowsNoDatagramDataAtPacketEnd()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30 }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal(0, frame.DatagramData.Length);
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDatagramWithoutLength_RoundTripsRepresentativeShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

[Requirement("REQ-QUIC-RFC9221-S4-0004")]
public sealed class REQ_QUIC_RFC9221_S4_0004_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramWithLength_ParsesLengthBeforeData()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x02, 0x10, 0x11, 0xFF }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal([0x10, 0x11], frame.DatagramData.ToArray());
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramWithLength_AllowsTwoByteLengthEncoding()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x40, 0x01, 0xAA }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal([0xAA], frame.DatagramData.ToArray());
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzDatagramWithLength_RoundTripsRepresentativeShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

[Requirement("REQ-QUIC-RFC9221-S4-0005")]
public sealed class REQ_QUIC_RFC9221_S4_0005_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramCodec_FormatsAndParsesEmptyPayload()
    {
        QuicDatagramFrame frame = new()
        {
            FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
            DatagramData = Array.Empty<byte>(),
        };
        Span<byte> destination = stackalloc byte[4];

        Assert.True(QuicFrameCodec.TryFormatDatagramFrame(frame, destination, out int bytesWritten));
        Assert.Equal(2, bytesWritten);
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(destination[..bytesWritten].ToArray(), out QuicDatagramFrame parsed, out int bytesConsumed));
        Assert.Equal(0, parsed.DatagramData.Length);
        Assert.Equal(bytesWritten, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramWithoutLength_AllowsEmptyPayloadAtPacketEnd()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x30 }, out QuicDatagramFrame parsed, out int bytesConsumed));

        Assert.Equal(0, parsed.DatagramData.Length);
        Assert.Equal(1, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzEmptyDatagramPayload_RoundTripsRepresentativeShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}

[Requirement("REQ-QUIC-RFC9221-S4-0006")]
public sealed class REQ_QUIC_RFC9221_S4_0006_Focused
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramWithLength_AcceptsLengthEqualToRemainingPayload()
    {
        Assert.True(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x02, 0x10, 0x11 }, out QuicDatagramFrame frame, out int bytesConsumed));

        Assert.Equal([0x10, 0x11], frame.DatagramData.ToArray());
        Assert.Equal(4, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatagramWithLength_RejectsLengthLargerThanRemainingPayload()
    {
        Assert.False(QuicFrameCodec.TryParseDatagramFrame(new byte[] { 0x31, 0x02, 0x10 }, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzMalformedDatagramLength_RejectsTruncatedShapes()
    {
        QuicFrameCodecFuzzSupport.FuzzDatagramFrame();
    }
}
