namespace Incursa.Quic.Tests;

public sealed class QuicStreamIdTests
{
    public static TheoryData<ulong, QuicStreamType, bool, bool> StreamIdCases => new()
    {
        { 0, QuicStreamType.ClientInitiatedBidirectional, true, true },
        { 1, QuicStreamType.ServerInitiatedBidirectional, false, true },
        { 2, QuicStreamType.ClientInitiatedUnidirectional, true, false },
        { 3, QuicStreamType.ServerInitiatedUnidirectional, false, false },
        { 4, QuicStreamType.ClientInitiatedBidirectional, true, true },
        { 5, QuicStreamType.ServerInitiatedBidirectional, false, true },
    };

    [Theory]
    [MemberData(nameof(StreamIdCases))]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_ExposesStreamTypeClassification(
        ulong value,
        QuicStreamType expectedStreamType,
        bool isClientInitiated,
        bool isBidirectional)
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(value);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(value, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(expectedStreamType, streamId.StreamType);
        Assert.Equal(isClientInitiated, streamId.IsClientInitiated);
        Assert.Equal(!isClientInitiated, streamId.IsServerInitiated);
        Assert.Equal(isBidirectional, streamId.IsBidirectional);
        Assert.Equal(!isBidirectional, streamId.IsUnidirectional);
    }

    [Theory]
    [InlineData(new byte[] { 0x40 })]
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Trait("Category", "Negative")]
    public void TryParseStreamIdentifier_RejectsTruncatedEncodings(byte[] encoded)
    {
        Assert.False(QuicStreamParser.TryParseStreamIdentifier(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
    [Trait("Category", "Positive")]
    public void TryParseStreamIdentifier_AcceptsTheMaximumRepresentableStreamId()
    {
        byte[] encoded = QuicStreamTestData.BuildStreamIdentifier(QuicVariableLengthInteger.MaxValue);

        Assert.True(QuicStreamParser.TryParseStreamIdentifier(encoded, out QuicStreamId streamId, out int bytesConsumed));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, streamId.Value);
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicStreamType.ServerInitiatedUnidirectional, streamId.StreamType);
        Assert.False(streamId.IsClientInitiated);
        Assert.True(streamId.IsServerInitiated);
        Assert.False(streamId.IsBidirectional);
        Assert.True(streamId.IsUnidirectional);
    }
}
