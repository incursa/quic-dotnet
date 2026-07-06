// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S5P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void LongHeaderConnectionIdFuzz_PreservesSourceAndDestinationConnectionIdFields()
    {
        Random random = new(0x5150_0008);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] destinationConnectionId = RandomBytes(random, iteration % 21);
            byte[] sourceConnectionId = RandomBytes(random, (iteration * 3) % 21);
            byte[] versionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: [],
                packetNumber: [0x01],
                protectedPayload: RandomBytes(random, random.Next(1, 8)));
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: QuicVersionNegotiation.Version1,
                destinationConnectionId,
                sourceConnectionId,
                versionSpecificData);

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(destinationConnectionId.Length, header.DestinationConnectionIdLength);
            Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
            Assert.Equal(sourceConnectionId.Length, header.SourceConnectionIdLength);
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
            Assert.True(versionSpecificData.AsSpan().SequenceEqual(header.VersionSpecificData));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0010")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ShortHeaderRoutingFuzz_UsesEndpointSelectedConnectionIdAndRegisteredLength()
    {
        Random random = new(0x5150_0010);

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(4);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity path = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{40 + iteration}",
                localAddress: "192.0.2.40",
                remotePort: 44000 + iteration,
                localPort: 4433);
            byte[] destinationConnectionId = RandomBytes(random, 1 + (iteration % 8));
            byte[] mismatchedConnectionId = [.. destinationConnectionId];
            mismatchedConnectionId[0] ^= 0xFF;
            byte[] routedDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [.. destinationConnectionId, 0xA0, 0xA1]);
            byte[] unroutableDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [.. mismatchedConnectionId, 0xA0]);

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, path));
            Assert.True(endpoint.TryRegisterConnectionId(handle, destinationConnectionId));

            Assert.True(QuicPacketParser.TryParseShortHeader(routedDatagram, out QuicShortHeaderPacket shortHeader));
            Assert.Equal(QuicHeaderForm.Short, shortHeader.HeaderForm);
            Assert.True(shortHeader.Remainder.StartsWith(destinationConnectionId));

            QuicConnectionIngressResult routed = endpoint.ReceiveDatagram(routedDatagram, path);
            QuicConnectionIngressResult unroutable = endpoint.ReceiveDatagram(unroutableDatagram, path);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, routed.Disposition);
            Assert.Equal(handle, routed.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unroutable.Disposition);
            Assert.Null(unroutable.Handle);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void VersionNegotiationFuzz_EchoesClientSelectedConnectionIds()
    {
        Random random = new(0x5150_0012);
        Span<byte> destination = stackalloc byte[128];

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] clientDestinationConnectionId = RandomBytes(random, iteration % 21);
            byte[] clientSourceConnectionId = RandomBytes(random, (iteration * 5) % 21);
            uint[] serverSupportedVersions =
            [
                QuicVersionNegotiation.Version1,
                0x1122_3300u + (uint)iteration,
            ];

            Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
                0xAABB_CCDD,
                clientDestinationConnectionId,
                clientSourceConnectionId,
                serverSupportedVersions,
                destination,
                out int bytesWritten));

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(destination[..bytesWritten], out QuicVersionNegotiationPacket packet));
            Assert.True(clientSourceConnectionId.AsSpan().SequenceEqual(packet.DestinationConnectionId));
            Assert.True(clientDestinationConnectionId.AsSpan().SequenceEqual(packet.SourceConnectionId));
            Assert.Equal(serverSupportedVersions.Length, packet.SupportedVersionCount);
            Assert.Equal(serverSupportedVersions[0], packet.GetSupportedVersion(0));
            Assert.Equal(serverSupportedVersions[1], packet.GetSupportedVersion(1));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroLengthConnectionIdFuzz_RoutesOnlyByKnownLocalAddressAndPreventsConcurrentReuse()
    {
        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
            QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{80 + iteration}",
                localAddress: "192.0.2.80",
                remotePort: 45000 + iteration,
                localPort: 4433);
            QuicConnectionPathIdentity matchingLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{112 + iteration}",
                localAddress: "192.0.2.80",
                remotePort: 45100 + iteration,
                localPort: 4433);
            QuicConnectionPathIdentity mismatchedLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: $"203.0.113.{112 + iteration}",
                localAddress: "192.0.2.81",
                remotePort: 45100 + iteration,
                localPort: 4433);
            byte[] shortHeaderDatagram = QuicHeaderTestData.BuildShortHeader(0x00, [0xA0]);

            Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
            Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, registeredPath));
            Assert.True(endpoint.TryRegisterConnectionId(firstHandle, ReadOnlySpan<byte>.Empty));

            Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
            Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, registeredPath));
            Assert.False(endpoint.TryRegisterConnectionId(secondHandle, ReadOnlySpan<byte>.Empty));

            QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(shortHeaderDatagram, matchingLocalAddress);
            QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(shortHeaderDatagram, mismatchedLocalAddress);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
            Assert.Equal(firstHandle, matched.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
            Assert.Null(unmatched.Handle);
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
