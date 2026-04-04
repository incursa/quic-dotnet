using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicStreamIdPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
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
