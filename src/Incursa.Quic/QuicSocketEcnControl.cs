// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;

namespace Incursa.Quic;

/// <summary>
/// Applies best-effort ECN markings to runtime-owned UDP sockets.
/// </summary>
internal static class QuicSocketEcnControl
{
    internal static bool TrySetEcnMarkingIfPossible(Socket socket, QuicEcnMarking ecnMarking)
    {
        ArgumentNullException.ThrowIfNull(socket);

        int typeOfService = ecnMarking switch
        {
            QuicEcnMarking.NotEct => 0,
            QuicEcnMarking.Ect0 => 0x02,
            QuicEcnMarking.Ect1 => 0x01,
            _ => 0,
        };

        return TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService)
            || TrySetSocketOption(socket, SocketOptionLevel.IPv6, typeOfService);
    }

    private static bool TrySetSocketOption(Socket socket, SocketOptionLevel level, int typeOfService)
    {
        try
        {
            socket.SetSocketOption(level, SocketOptionName.TypeOfService, typeOfService);
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
}
