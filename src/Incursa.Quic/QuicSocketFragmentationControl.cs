using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Applies best-effort IPv4 fragmentation controls to runtime-owned UDP sockets.
/// </summary>
internal static class QuicSocketFragmentationControl
{
    internal static bool TryEnableDontFragmentIfPossible(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);

        if (socket.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        try
        {
            socket.DontFragment = true;
            return socket.DontFragment;
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
    }
}
