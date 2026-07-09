// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic;

// CONTEXT: Packet-information enablement is best-effort because different socket families and
// platforms expose different ancillary-data APIs; the runtime falls back to the peer endpoint when
// local packet info is unavailable.
// SEE: ResolveLocalEndPoint
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

    internal sealed class LocalEndPointCache
    {
        private IPAddress? cachedPacketInformationAddress;
        private int cachedPort = -1;
        private IPEndPoint? cachedEndPoint;

        internal IPEndPoint Resolve(IPEndPoint fallback, IPAddress? packetInformationAddress)
        {
            ArgumentNullException.ThrowIfNull(fallback);

            if (packetInformationAddress is null
                || packetInformationAddress.Equals(IPAddress.Any)
                || packetInformationAddress.Equals(IPAddress.IPv6Any))
            {
                return fallback;
            }

            if (cachedEndPoint is not null
                && cachedPort == fallback.Port
                && cachedPacketInformationAddress is not null
                && cachedPacketInformationAddress.Equals(packetInformationAddress))
            {
                return cachedEndPoint;
            }

            cachedPacketInformationAddress = packetInformationAddress;
            cachedPort = fallback.Port;
            cachedEndPoint = new IPEndPoint(packetInformationAddress, fallback.Port);
            return cachedEndPoint;
        }
    }
}
