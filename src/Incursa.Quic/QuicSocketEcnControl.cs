// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;

namespace Incursa.Quic;

// CONTEXT: ECN socket marking is best-effort and platform-specific, so the helper maps the QUIC
// marking to the native TypeOfService bits and falls back across IP families.
// SEE: QuicEcnMarking
/// <summary>
/// Applies best-effort ECN markings to runtime-owned UDP sockets.
/// </summary>
internal static class QuicSocketEcnControl
{
    private const string ReceiveMetadataUnsupportedReason =
        "The managed socket receive path uses Socket.ReceiveMessageFromAsync and SocketReceiveMessageFromResult " +
        "packet information, which do not expose IP_TOS or IPV6_TCLASS ancillary ECN bits. Receive-side ECN count " +
        "promotion needs a native or control-message receive path before local interop proof can claim received IP " +
        "packet ECN metadata.";

    internal static QuicReceiveEcnMetadataCapability GetReceiveEcnMetadataCapability()
    {
        return new QuicReceiveEcnMetadataCapability(
            IsSupported: false,
            Reason: ReceiveMetadataUnsupportedReason);
    }

    internal static bool TryGetReceivedEcnCounts(
        SocketReceiveMessageFromResult receiveResult,
        out QuicEcnCounts ecnCounts)
    {
        ecnCounts = default;
        _ = receiveResult;
        return false;
    }

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

internal readonly record struct QuicReceiveEcnMetadataCapability(bool IsSupported, string Reason);
