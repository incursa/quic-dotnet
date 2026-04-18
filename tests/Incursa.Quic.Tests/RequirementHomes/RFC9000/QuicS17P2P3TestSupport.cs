using System.Collections.Generic;
using System.Linq;

namespace Incursa.Quic.Tests;

internal static class QuicS17P2P3TestSupport
{
    internal static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    internal static readonly byte[] InitialSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    internal static readonly QuicConnectionPathIdentity BootstrapPath =
        new("203.0.113.10", "198.51.100.20", 443, 12345);

    internal static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    internal static readonly byte[] PacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    internal static QuicConnectionRuntime CreateClientRuntime(
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null)
    {
        byte[] localHandshakePrivateKey = CreateScalar(0x11);
        QuicConnectionRuntime clientRuntime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            tlsRole: QuicTlsRole.Client,
            localHandshakePrivateKey: localHandshakePrivateKey,
            detachedResumptionTicketSnapshot: detachedResumptionTicketSnapshot);

        Assert.True(clientRuntime.TryConfigureInitialPacketProtection(InitialDestinationConnectionId));
        Assert.True(clientRuntime.TrySetBootstrapOutboundPath(BootstrapPath));
        Assert.True(clientRuntime.TrySetHandshakeSourceConnectionId(InitialSourceConnectionId));
        return clientRuntime;
    }

    internal static QuicTransportParameters CreateBootstrapLocalTransportParameters()
    {
        return QuicLoopbackEstablishmentTestSupport.CreateSupportedTransportParameters(InitialSourceConnectionId);
    }

    internal static QuicHandshakeFlowCoordinator CreateBootstrapPacketCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(InitialDestinationConnectionId, InitialSourceConnectionId);
    }

    internal static QuicHandshakeFlowCoordinator CreatePacketCoordinator()
    {
        return new QuicHandshakeFlowCoordinator(PacketConnectionId, PacketSourceConnectionId);
    }

    internal static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial(QuicTlsEncryptionLevel encryptionLevel)
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            encryptionLevel,
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

    internal static byte[] CreatePingPayload()
    {
        return QuicS12P3TestSupport.CreatePingPayload();
    }

    internal static byte[] CreateAckResponsePayload()
    {
        return QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
        });
    }

    internal static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    internal static byte[] BuildExpectedZeroRttPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicHandshakeFlowCoordinator coordinator = CreateBootstrapPacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedZeroRttApplicationPacket(
            applicationPayload,
            material,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    internal static byte[] BuildExpectedOneRttPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase)
    {
        QuicHandshakeFlowCoordinator coordinator = CreatePacketCoordinator();
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            keyPhase,
            out byte[] protectedPacket));
        return protectedPacket;
    }

    internal static QuicConnectionSendDatagramEffect[] GetInitialSendEffects(IEnumerable<QuicConnectionEffect> effects)
    {
        return effects.OfType<QuicConnectionSendDatagramEffect>()
            .Where(effect => IsInitialPacket(effect.Datagram.Span))
            .ToArray();
    }

    internal static QuicConnectionSendDatagramEffect[] GetZeroRttSendEffects(IEnumerable<QuicConnectionEffect> effects)
    {
        return effects.OfType<QuicConnectionSendDatagramEffect>()
            .Where(effect => IsZeroRttPacket(effect.Datagram.Span))
            .ToArray();
    }

    internal static bool IsInitialPacket(ReadOnlySpan<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader)
            && longHeader.Version == 1
            && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.Initial;
    }

    internal static bool IsZeroRttPacket(ReadOnlySpan<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader)
            && longHeader.Version == 1
            && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.ZeroRtt;
    }

    private static byte[] CreateScalar(byte value)
    {
        byte[] scalar = new byte[32];
        scalar[^1] = value;
        return scalar;
    }
}
