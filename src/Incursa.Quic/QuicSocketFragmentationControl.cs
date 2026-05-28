// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
