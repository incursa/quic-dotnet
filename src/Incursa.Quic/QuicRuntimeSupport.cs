using System.Net.Sockets;
using System.Security.Cryptography;

namespace Incursa.Quic;

internal static class QuicRuntimeSupport
{
    private static readonly Lazy<bool> supported = new(EvaluateIsSupported);

    internal static bool IsSupported => supported.Value;

    private static bool EvaluateIsSupported()
    {
        try
        {
            if (!AesGcm.IsSupported)
            {
                return false;
            }

            if (!Socket.OSSupportsIPv4 && !Socket.OSSupportsIPv6)
            {
                return false;
            }

            using Socket socket = Socket.OSSupportsIPv4
                ? new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp)
                : new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);

            using ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            _ = socket;
            _ = ecdh;
            _ = ecdsa;
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (NotSupportedException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
