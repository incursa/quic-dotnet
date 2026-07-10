// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

internal static class QuicSocketReceiveLoopWakeup
{
    internal static bool TryWake(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);

        try
        {
            if (socket.LocalEndPoint is not IPEndPoint boundEndPoint)
            {
                return false;
            }

            IPAddress wakeAddress = boundEndPoint.Address;
            if (wakeAddress.Equals(IPAddress.Any))
            {
                wakeAddress = IPAddress.Loopback;
            }
            else if (wakeAddress.Equals(IPAddress.IPv6Any))
            {
                wakeAddress = IPAddress.IPv6Loopback;
            }

            IPEndPoint wakeEndPoint = new(wakeAddress, boundEndPoint.Port);
            ReadOnlySpan<byte> wakeDatagram = [0];

            return socket.SendTo(wakeDatagram, SocketFlags.None, wakeEndPoint) == wakeDatagram.Length;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (SocketException)
        {
            return false;
        }
    }
}
