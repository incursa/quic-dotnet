using System.Net.Sockets;
using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Probes the current process for the runtime capabilities required by Incursa QUIC support.
/// </summary>
internal static class QuicRuntimeSupport
{
    // Probe once and cache the result because the capability checks touch platform-specific primitives.
    private static readonly Lazy<bool> supported = new(EvaluateIsSupported);

    /// <summary>
    /// Gets a value that indicates whether the current runtime environment can support QUIC operations.
    /// </summary>
    internal static bool IsSupported => supported.Value;

    /// <summary>
    /// Performs the runtime capability probe used by <see cref="IsSupported"/>.
    /// </summary>
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
