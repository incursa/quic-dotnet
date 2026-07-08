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
    private static readonly EcnSocketOptionSupport GlobalSocketOptionSupport = new();
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

        EcnSocketOptionSupport support = SocketOptionSupport.GetValue(socket, _ => new EcnSocketOptionSupport());
        if (ecnMarking == QuicEcnMarking.NotEct)
        {
            return TryClearEcnMarkingIfPreviouslyEnabled(socket, support);
        }

        int typeOfService = ecnMarking switch
        {
            QuicEcnMarking.Ect0 => 0x02,
            QuicEcnMarking.Ect1 => 0x01,
            _ => 0,
        };

        return socket.AddressFamily switch
        {
            AddressFamily.InterNetwork => TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService, support, ipv6: false),
            AddressFamily.InterNetworkV6 => TrySetSocketOption(socket, SocketOptionLevel.IPv6, typeOfService, support, ipv6: true)
                || TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService, support, ipv6: false),
            _ => false,
        };
    }

    private static bool TryClearEcnMarkingIfPreviouslyEnabled(Socket socket, EcnSocketOptionSupport support)
    {
        return socket.AddressFamily switch
        {
            AddressFamily.InterNetwork => support.GetState(ipv6: false) != SupportAvailable ||
                TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService: 0, support, ipv6: false),
            AddressFamily.InterNetworkV6 => ClearKnownSupportedIpv6Options(socket, support),
            _ => false,
        };
    }

    private static bool ClearKnownSupportedIpv6Options(Socket socket, EcnSocketOptionSupport support)
    {
        bool clearIpv6 = support.GetState(ipv6: true) == SupportAvailable;
        bool clearIp = support.GetState(ipv6: false) == SupportAvailable;

        if (!clearIpv6 && !clearIp)
        {
            return true;
        }

        bool cleared = false;
        if (clearIpv6)
        {
            cleared |= TrySetSocketOption(socket, SocketOptionLevel.IPv6, typeOfService: 0, support, ipv6: true);
        }

        if (clearIp)
        {
            cleared |= TrySetSocketOption(socket, SocketOptionLevel.IP, typeOfService: 0, support, ipv6: false);
        }

        return cleared;
    }

    private static bool TrySetSocketOption(
        Socket socket,
        SocketOptionLevel level,
        int typeOfService,
        EcnSocketOptionSupport support,
        bool ipv6)
    {
        if (GlobalSocketOptionSupport.GetState(ipv6) == SupportUnavailable ||
            support.GetState(ipv6) == SupportUnavailable)
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
            GlobalSocketOptionSupport.MarkUnavailable(ipv6);
            support.MarkUnavailable(ipv6);
            return false;
        }
        catch (SocketException ex) when (IsSocketOptionUnsupported(ex))
        {
            GlobalSocketOptionSupport.MarkUnavailable(ipv6);
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
            GlobalSocketOptionSupport.MarkUnavailable(ipv6);
            support.MarkUnavailable(ipv6);
            return false;
        }
        catch (ArgumentException)
        {
            GlobalSocketOptionSupport.MarkUnavailable(ipv6);
            support.MarkUnavailable(ipv6);
            return false;
        }
    }

    private static bool IsSocketOptionUnsupported(SocketException exception)
    {
        return exception.SocketErrorCode is SocketError.InvalidArgument
            or SocketError.ProtocolOption
            or SocketError.OperationNotSupported
            or SocketError.AddressFamilyNotSupported;
    }

    internal static void ResetGlobalSocketOptionSupportForTest()
    {
        GlobalSocketOptionSupport.Reset();
    }

    internal static void MarkGlobalSocketOptionUnavailableForTest(bool ipv6)
    {
        GlobalSocketOptionSupport.MarkUnavailable(ipv6);
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

        public void Reset()
        {
            Volatile.Write(ref ip, SupportUnknown);
            Volatile.Write(ref ipv6, SupportUnknown);
        }
    }
}

internal readonly record struct QuicReceiveEcnMetadataCapability(bool IsSupported, string Reason);
