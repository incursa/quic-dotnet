using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamIdPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
    [Requirement("REQ-QUIC-STRM-0001")]
    [Requirement("REQ-QUIC-STRM-0002")]
    [Requirement("REQ-QUIC-STRM-0003")]
    [Requirement("REQ-QUIC-STRM-0004")]
    [Trait("Category", "Property")]
    public void TryParseStreamIdentifier_RoundTripsTheStreamTypeBits(ulong value)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(value, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal((QuicStreamType)(value & 0x03), streamId.StreamType);
        Assert.Equal((value & 0x01) == 0, streamId.IsClientInitiated);
        Assert.Equal((value & 0x01) != 0, streamId.IsServerInitiated);
        Assert.Equal((value & 0x02) == 0, streamId.IsBidirectional);
        Assert.Equal((value & 0x02) != 0, streamId.IsUnidirectional);
    }
}
