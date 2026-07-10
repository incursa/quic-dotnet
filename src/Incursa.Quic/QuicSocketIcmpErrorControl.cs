// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;

namespace Incursa.Quic;

internal static class QuicSocketIcmpErrorControl
{
    private const int SioUdpConnectionReset = unchecked((int)0x9800000C);
    private static readonly byte[] DisableReporting = new byte[sizeof(int)];

    internal static bool TryDisablePortUnreachableReporting(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);

        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            _ = socket.IOControl(SioUdpConnectionReset, DisableReporting, null);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
