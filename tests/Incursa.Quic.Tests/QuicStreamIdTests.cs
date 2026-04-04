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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0003">Each stream MUST be identified within a connection by a numeric value called the stream ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0004">A stream ID MUST be a 62-bit integer in the range 0 to 2^62-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0006">Stream IDs MUST be encoded as variable-length integers.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0008">The least significant bit of a stream ID MUST identify the initiator of the stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0009">Client-initiated streams MUST have even-numbered stream IDs with the least significant bit set to 0.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0010">Server-initiated streams MUST have odd-numbered stream IDs with the least significant bit set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0011">The second least significant bit of a stream ID MUST distinguish bidirectional streams from unidirectional streams, with 0 indicating bidirectional and 1 indicating unidirectional.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0004">A stream ID MUST be a 62-bit integer in the range 0 to 2^62-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0006">Stream IDs MUST be encoded as variable-length integers.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamIdentifier_RejectsTruncatedEncodings(byte[] encoded)
    {
        Assert.False(QuicStreamParser.TryParseStreamIdentifier(encoded, out _, out _));
    }

    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0003">Each stream MUST be identified within a connection by a numeric value called the stream ID.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0004">A stream ID MUST be a 62-bit integer in the range 0 to 2^62-1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0006">Stream IDs MUST be encoded as variable-length integers.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0008">The least significant bit of a stream ID MUST identify the initiator of the stream.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0010">Server-initiated streams MUST have odd-numbered stream IDs with the least significant bit set to 1.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P1-0011">The second least significant bit of a stream ID MUST distinguish bidirectional streams from unidirectional streams, with 0 indicating bidirectional and 1 indicating unidirectional.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S2P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0008")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S2P1-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
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
