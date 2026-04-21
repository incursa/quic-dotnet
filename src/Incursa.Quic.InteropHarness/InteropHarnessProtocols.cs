using System.Net.Security;

namespace Incursa.Quic.InteropHarness;

internal static class InteropHarnessProtocols
{
    internal static readonly SslApplicationProtocol QuicInterop = new("hq-interop");
}
