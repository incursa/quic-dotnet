namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P2-0012")]
public sealed class REQ_QUIC_RFC9000_S7P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerInitialResponseUsesTheClientInitialSourceConnectionIdAsDestination()
    {
        byte[] originalDestinationConnectionId = [0x11, 0x12, 0x13, 0x14];
        byte[] clientSourceConnectionId = [0x21, 0x22, 0x23, 0x24];
        byte[] serverSourceConnectionId = [0x31, 0x32, 0x33, 0x34];

        ServerHandshakeFlight serverFlight = CreateServerFlightFromClientInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.InitialPacket,
            clientSourceConnectionId,
            serverSourceConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerInitialResponseDoesNotUseTheOriginalDestinationConnectionIdAsDestination()
    {
        byte[] originalDestinationConnectionId = [0x41, 0x42, 0x43, 0x44];
        byte[] clientSourceConnectionId = [0x51, 0x52, 0x53, 0x54];
        byte[] serverSourceConnectionId = [0x61, 0x62, 0x63, 0x64];

        ServerHandshakeFlight serverFlight = CreateServerFlightFromClientInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId);

        Assert.True(QuicPacketParser.TryParseLongHeader(serverFlight.InitialPacket, out QuicLongHeaderPacket header));
        Assert.False(header.DestinationConnectionId.SequenceEqual(originalDestinationConnectionId));
        Assert.True(header.DestinationConnectionId.SequenceEqual(clientSourceConnectionId));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerInitialResponseCanUseAMaximumLengthClientInitialSourceConnectionId()
    {
        byte[] originalDestinationConnectionId = [0x81, 0x82, 0x83, 0x84];
        byte[] clientSourceConnectionId =
        [
            0xA0, 0xA1, 0xA2, 0xA3,
            0xA4, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAA, 0xAB,
            0xAC, 0xAD, 0xAE, 0xAF,
            0xB0, 0xB1, 0xB2, 0xB3
        ];
        byte[] serverSourceConnectionId = [0x91, 0x92, 0x93, 0x94];

        ServerHandshakeFlight serverFlight = CreateServerFlightFromClientInitial(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.InitialPacket,
            clientSourceConnectionId,
            serverSourceConnectionId);
    }

    private static ServerHandshakeFlight CreateServerFlightFromClientInitial(
        ReadOnlySpan<byte> originalDestinationConnectionId,
        ReadOnlySpan<byte> clientSourceConnectionId,
        ReadOnlySpan<byte> serverSourceConnectionId)
    {
        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(clientRuntime, clientSourceConnectionId);

        return QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x21),
            clientInitialDatagrams);
    }
}
