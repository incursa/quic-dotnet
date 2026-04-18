namespace Incursa.Quic.Tests;

internal static class QuicS17P1TestSupport
{
    internal static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    internal static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    internal static readonly byte[] HandshakeDestinationConnectionId =
    [
        0x11, 0x12, 0x13, 0x14,
    ];

    internal static readonly byte[] HandshakeSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    internal static readonly byte[] ApplicationDestinationConnectionId =
    [
        0x31, 0x32, 0x33, 0x34,
    ];

    internal static readonly byte[] ApplicationSourceConnectionId =
    [
        0x41, 0x42, 0x43, 0x44,
    ];

    internal static QuicHandshakeFlowCoordinator CreateInitialCoordinator()
    {
        return new(InitialDestinationConnectionId, InitialSourceConnectionId);
    }

    internal static QuicHandshakeFlowCoordinator CreateHandshakeCoordinator()
    {
        return new(HandshakeDestinationConnectionId, HandshakeSourceConnectionId);
    }

    internal static QuicHandshakeFlowCoordinator CreateApplicationCoordinator()
    {
        return new(ApplicationDestinationConnectionId, ApplicationSourceConnectionId);
    }

    internal static ulong ReadPacketNumber(ReadOnlySpan<byte> packetNumberBytes)
    {
        ulong packetNumber = 0;
        foreach (byte packetNumberByte in packetNumberBytes)
        {
            packetNumber = (packetNumber << 8) | packetNumberByte;
        }

        return packetNumber;
    }
}
