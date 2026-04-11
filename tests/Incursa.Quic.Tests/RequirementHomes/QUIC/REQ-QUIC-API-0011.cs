using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0011">QuicConnection.IsSupported and QuicListener.IsSupported expose the same deterministic runtime capability value for the supported managed QUIC loopback slice, and that value reflects only whether the current runtime can execute the repository's supported connection/listener path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0011")]
public sealed class REQ_QUIC_API_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionAndQuicListener_IsSupported_TrackTheCurrentRuntimeCapability()
    {
        bool expectedSupported = ProbeRuntimeCapability();

        Assert.Equal(expectedSupported, QuicConnection.IsSupported);
        Assert.Equal(expectedSupported, QuicListener.IsSupported);
        Assert.Equal(QuicConnection.IsSupported, QuicListener.IsSupported);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionAndQuicListener_IsSupported_ArePublicStaticBooleans()
    {
        PropertyInfo? connectionProperty = typeof(QuicConnection).GetProperty(
            nameof(QuicConnection.IsSupported),
            BindingFlags.Public | BindingFlags.Static);
        PropertyInfo? listenerProperty = typeof(QuicListener).GetProperty(
            nameof(QuicListener.IsSupported),
            BindingFlags.Public | BindingFlags.Static);

        Assert.NotNull(connectionProperty);
        Assert.NotNull(listenerProperty);

        Assert.True(connectionProperty!.GetMethod!.IsStatic);
        Assert.True(listenerProperty!.GetMethod!.IsStatic);
        Assert.Equal(typeof(bool), connectionProperty.PropertyType);
        Assert.Equal(typeof(bool), listenerProperty.PropertyType);
    }

    private static bool ProbeRuntimeCapability()
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
