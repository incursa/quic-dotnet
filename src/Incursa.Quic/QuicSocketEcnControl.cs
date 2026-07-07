// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Threading;

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
    private const int SupportUnknown = 0;
    private const int SupportAvailable = 1;
    private const int SupportUnavailable = -1;
    private static readonly ConditionalWeakTable<Socket, EcnSocketOptionSupport> SocketOptionSupport = new();

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

        EcnSocketOptionSupport support = SocketOptionSupport.GetValue(socket, _ => new EcnSocketOptionSupport());
        return socket.AddressFamily switch
        {
            AddressFamily.InterNetwork => TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService, support, ipv6: false),
            AddressFamily.InterNetworkV6 => TrySetSocketOption(socket, SocketOptionLevel.IPv6, typeOfService, support, ipv6: true)
                || TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService, support, ipv6: false),
            _ => false,
        };
    }

    private static bool TrySetSocketOption(
        Socket socket,
        SocketOptionLevel level,
        int typeOfService,
        EcnSocketOptionSupport support,
        bool ipv6)
    {
        if (support.GetState(ipv6) == SupportUnavailable)
        {
            return false;
        }

        try
        {
            socket.SetSocketOption(level, SocketOptionName.TypeOfService, typeOfService);
            support.MarkAvailable(ipv6);
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            support.MarkUnavailable(ipv6);
            return false;
        }
        catch (SocketException)
        {
            support.MarkUnavailable(ipv6);
            return false;
        }
        catch (NotSupportedException)
        {
            support.MarkUnavailable(ipv6);
            return false;
        }
        catch (ArgumentException)
        {
            support.MarkUnavailable(ipv6);
            return false;
        }
    }

    private sealed class EcnSocketOptionSupport
    {
        private int ip = SupportUnknown;
        private int ipv6 = SupportUnknown;

        public int GetState(bool ipv6)
        {
            return ipv6
                ? Volatile.Read(ref this.ipv6)
                : Volatile.Read(ref ip);
        }

        public void MarkAvailable(bool ipv6)
        {
            if (ipv6)
            {
                Volatile.Write(ref this.ipv6, SupportAvailable);
            }
            else
            {
                Volatile.Write(ref ip, SupportAvailable);
            }
        }

        public void MarkUnavailable(bool ipv6)
        {
            if (ipv6)
            {
                Volatile.Write(ref this.ipv6, SupportUnavailable);
            }
            else
            {
                Volatile.Write(ref ip, SupportUnavailable);
            }
        }
    }
}

internal readonly record struct QuicReceiveEcnMetadataCapability(bool IsSupported, string Reason);
