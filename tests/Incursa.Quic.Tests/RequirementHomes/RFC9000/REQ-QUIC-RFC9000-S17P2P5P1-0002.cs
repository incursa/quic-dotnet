namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0002">This value MUST NOT be equal to the Destination Connection ID field of the packet sent by the client.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0002")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5P1-0002">This value MUST NOT be equal to the Destination Connection ID field of the packet sent by the client.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5P1-0002")]
    public void TryBuildRetryPacket_RejectsRetrySourceConnectionIdsThatMatchTheClientsInitialDestinationConnectionId()
    {
        byte[] clientInitialDestinationConnectionId =
        [
            0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];
        byte[] retryToken =
        [
            0x74, 0x6F, 0x6B, 0x65, 0x6E,
        ];

        Assert.False(QuicRetryIntegrity.TryBuildRetryPacket(
            clientInitialDestinationConnectionId,
            retryPacketDestinationConnectionId,
            clientInitialDestinationConnectionId,
            retryToken,
            out byte[] retryPacket));
        Assert.Empty(retryPacket);
    }
}
