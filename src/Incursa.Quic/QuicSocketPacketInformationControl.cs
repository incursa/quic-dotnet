using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Applies best-effort packet information controls to runtime-owned UDP sockets.
/// </summary>
internal static class QuicSocketPacketInformationControl
{
    internal static bool TryEnablePacketInformationIfPossible(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);

        return TrySetSocketOption(socket, SocketOptionLevel.IP)
            || TrySetSocketOption(socket, SocketOptionLevel.IPv6);
    }

    private static bool TrySetSocketOption(Socket socket, SocketOptionLevel level)
    {
        try
        {
            socket.SetSocketOption(level, SocketOptionName.PacketInformation, true);
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    internal static IPEndPoint ResolveLocalEndPoint(IPEndPoint fallback, IPAddress? packetInformationAddress)
    {
        ArgumentNullException.ThrowIfNull(fallback);

        if (packetInformationAddress is null
            || packetInformationAddress.Equals(IPAddress.Any)
            || packetInformationAddress.Equals(IPAddress.IPv6Any))
        {
            return fallback;
        }

        return new IPEndPoint(packetInformationAddress, fallback.Port);
    }
}
