using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamIdPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
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
