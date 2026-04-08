namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0007")]
public sealed class REQ_QUIC_RFC9000_S4P6_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseMaxStreamsFrame_RejectsValuesAboveTheEncodingLimit()
    {
        ulong maximumStreamLimit = 1UL << 60;
        ulong oversizedMaximumStreamLimit = maximumStreamLimit + 1;

        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicVariableLengthInteger.TryFormat(oversizedMaximumStreamLimit, encoded[1..], out int encodedValueBytes));
        encoded[0] = 0x12;

        Assert.False(QuicFrameCodec.TryParseMaxStreamsFrame(encoded[..(encodedValueBytes + 1)], out QuicMaxStreamsFrame frame, out int bytesConsumed));
        Assert.Equal(default, frame);
        Assert.Equal(default, bytesConsumed);
    }
}
