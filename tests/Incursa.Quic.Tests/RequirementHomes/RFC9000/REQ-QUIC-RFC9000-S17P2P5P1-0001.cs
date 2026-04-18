namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0001">The server MUST include a connection ID of its choice in the Source Connection ID field.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0001">The server MUST include a connection ID of its choice in the Source Connection ID field.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0001")]
    public void TryBuildRetryPacket_IncludesTheServersChosenSourceConnectionId()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];
        byte[] retrySourceConnectionId = QuicListenerHost.GenerateDistinctServerSourceConnectionId(clientInitialDestinationConnectionId);
        byte[] retryToken =
        [
            0x74, 0x6F, 0x6B, 0x65, 0x6E,
        ];

        Assert.Equal(8, retrySourceConnectionId.Length);
        Assert.False(clientInitialDestinationConnectionId.AsSpan().SequenceEqual(retrySourceConnectionId));

        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            clientInitialDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));

        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
        Assert.Equal(QuicLongPacketTypeBits.Retry, header.LongPacketTypeBits);
        Assert.True(retryPacketDestinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
        Assert.True(retrySourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
    }
}
