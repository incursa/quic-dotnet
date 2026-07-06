// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class RFC9000_S7P2P2_HandshakeConnectionId_DeferredFuzzClosure
{
    [Theory]
    [InlineData(8, 4, 3, 0x20)]
    [InlineData(12, 8, 7, 0x40)]
    [Requirement("RFC9000-S7-2-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void HandshakeConnectionIdFuzz_LongHeaderPacketsEstablishBothEndpointConnectionIds(
        int originalDestinationLength,
        int clientInitialSourceLength,
        int serverSourceLength,
        int seed)
    {
        byte[] originalDestinationConnectionId = CreateConnectionId(originalDestinationLength, seed);
        byte[] clientInitialSourceConnectionId = CreateConnectionId(clientInitialSourceLength, seed + 0x20);
        byte[] serverSourceConnectionId = CreateConnectionId(serverSourceLength, seed + 0x40);

        using QuicConnectionRuntime clientRuntime =
            QuicS7P2ServerConnectionIdTestSupport.CreateClientRuntime(
                originalDestinationConnectionId,
                clientInitialSourceConnectionId);
        QuicConnectionSendDatagramEffect[] clientInitialDatagrams =
            QuicS7P2ServerConnectionIdTestSupport.BootstrapClient(
                clientRuntime,
                clientInitialSourceConnectionId);

        ServerHandshakeFlight serverFlight = QuicS7P2ServerConnectionIdTestSupport.CreateServerHandshakeFlight(
            originalDestinationConnectionId,
            clientInitialSourceConnectionId,
            serverSourceConnectionId,
            QuicS7P2ServerConnectionIdTestSupport.CreateScalar(unchecked((byte)(seed + 0x60))),
            clientInitialDatagrams);

        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.InitialPacket,
            observedAtTicks: 1).StateChanged);
        Assert.True(QuicS7P2ServerConnectionIdTestSupport.ReceivePacket(
            clientRuntime,
            serverFlight.HandshakePacket,
            observedAtTicks: 2).StateChanged);

        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            clientInitialDatagrams[0].Datagram.Span,
            originalDestinationConnectionId,
            clientInitialSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.InitialPacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
        QuicS7P2ServerConnectionIdTestSupport.AssertLongHeaderConnectionIds(
            serverFlight.HandshakePacket,
            clientInitialSourceConnectionId,
            serverSourceConnectionId);
    }

    [Theory]
    [InlineData(0, 1, 0x80)]
    [InlineData(4, 8, 0x90)]
    [InlineData(20, 20, 0xA0)]
    [Requirement("RFC9000-S7-2-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void VersionNegotiationConnectionIdFuzz_CopiesPeerSourceIntoResponseDestination(
        int clientDestinationLength,
        int clientSourceLength,
        int seed)
    {
        byte[] destination = new byte[128];
        byte[] clientDestinationConnectionId = CreateConnectionId(clientDestinationLength, seed);
        byte[] clientSourceConnectionId = CreateConnectionId(clientSourceLength, seed + 0x20);
        uint[] serverSupportedVersions =
        [
            QuicVersionNegotiation.Version1,
            0x11223344,
            unchecked((uint)(0xA0A0A0A0 + seed)),
        ];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            0xAABBCCDD,
            clientDestinationConnectionId,
            clientSourceConnectionId,
            serverSupportedVersions,
            destination,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            destination[..bytesWritten],
            out QuicVersionNegotiationPacket packet));
        Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
        Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
        Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
        foreach (uint supportedVersion in serverSupportedVersions)
        {
            Assert.True(packet.ContainsSupportedVersion(supportedVersion));
        }
    }

    private static byte[] CreateConnectionId(int length, int seed)
    {
        byte[] connectionId = new byte[length];
        for (int index = 0; index < connectionId.Length; index++)
        {
            connectionId[index] = unchecked((byte)(seed + (index * 11)));
        }

        return connectionId;
    }
}
