using System.Collections;
using System.Reflection;

namespace Incursa.Quic.Tests;

internal static class QuicS5P2PacketAssociationTestSupport
{
    internal static readonly byte[] RouteConnectionId = [0x30, 0x31];

    internal static (
        QuicConnectionRuntime Runtime,
        QuicConnectionRuntimeEndpoint Endpoint,
        QuicConnectionHandle Handle) CreateRegisteredEndpoint(
            ReadOnlySpan<byte> connectionId,
            QuicConnectionPathIdentity? pathIdentity = null)
    {
        QuicConnectionRuntime runtime = InteropEndpointHostTestSupport.CreateRuntime();
        QuicConnectionRuntimeEndpoint endpoint = new(1);
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        if (pathIdentity.HasValue)
        {
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity.Value));
        }

        Assert.True(endpoint.TryRegisterConnectionId(handle, connectionId));
        return (runtime, endpoint, handle);
    }

    internal static byte[] BuildHandshakeDatagram(ReadOnlySpan<byte> destinationConnectionId)
    {
        return QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram(destinationConnectionId);
    }

    internal static byte[] BuildShortHeaderDatagram(ReadOnlySpan<byte> destinationConnectionId)
    {
        return QuicHeaderTestData.BuildShortHeader(0x00, destinationConnectionId);
    }

    internal static byte[] BuildMaximumLengthConnectionId()
    {
        byte[] connectionId = new byte[QuicConnectionIdKey.MaximumLength];
        for (int i = 0; i < connectionId.Length; i++)
        {
            connectionId[i] = unchecked((byte)(0xA0 + i));
        }

        return connectionId;
    }

    internal static QuicConnectionRuntime CreateServerRuntimeWithInitialProtection(
        ReadOnlySpan<byte> initialDestinationConnectionId)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(initialDestinationConnectionId));
        return runtime;
    }

    internal static byte[] BuildProtectedClientInitialPacket(
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> plaintextPayload)
    {
        byte[] paddedPlaintextPayload = new byte[Math.Max(plaintextPayload.Length, 24)];
        plaintextPayload.CopyTo(paddedPlaintextPayload);

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId: initialDestinationConnectionId,
            sourceConnectionId:
            [
                0x21, 0x22, 0x23, 0x24,
            ],
            token: [],
            packetNumber:
            [
                0x01,
            ],
            plaintextPayload: paddedPlaintextPayload);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            initialDestinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);
        return protectedPacket;
    }

    internal static byte[] TamperLastByte(ReadOnlySpan<byte> packet)
    {
        byte[] mutatedPacket = packet.ToArray();
        mutatedPacket[^1] ^= 0xFF;
        return mutatedPacket;
    }

    internal static byte[] BuildProtectedHandshakePacket(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> prefixFramePayload,
        byte cryptoStart = 0x40)
    {
        Assert.True(runtime.TlsState.TryGetHandshakeOpenPacketProtectionMaterial(
            out QuicTlsPacketProtectionMaterial handshakeMaterial));

        QuicHandshakeFlowCoordinator coordinator = new(
            runtime.CurrentPeerDestinationConnectionId,
            runtime.CurrentHandshakeSourceConnectionId);
        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            CreateSequentialBytes(cryptoStart, 20),
            cryptoPayloadOffset: 0,
            prefixFramePayload,
            handshakeMaterial,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    internal static int GetBufferedEstablishmentHandshakePacketCount(QuicConnectionRuntime runtime)
    {
        FieldInfo field = typeof(QuicConnectionRuntime).GetField(
            "bufferedEstablishmentHandshakePackets",
            BindingFlags.Instance | BindingFlags.NonPublic)!;
        ICollection bufferedPackets = (ICollection)field.GetValue(runtime)!;
        return bufferedPackets.Count;
    }

    private static byte[] CreateSequentialBytes(byte start, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(start + i));
        }

        return bytes;
    }
}
