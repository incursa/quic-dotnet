// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Incursa.Quic;

/// <summary>
/// Sends UDP datagrams with Linux packet-info source-address selection.
/// </summary>
internal static partial class QuicSocketPacketInformationSender
{
    private const int NativeAddressFamilyInterNetwork = 2;
    private const int NativeAddressFamilyInterNetworkV6 = 10;
    private const int IpProtocolIp = 0;
    private const int IpProtocolIpv6 = 41;
    private const int IpPacketInformation = 8;
    private const int Ipv6PacketInformation = 50;
    private const int NativeSocketAddressInLength = 16;
    private const int NativeSocketAddressIn6Length = 28;
    private const int NativePacketInformationLength = 12;
    private const int NativePacketInformationV6Length = 20;
    private const int NativeSocketAddressFamilyOffset = 0;
    private const int NativeSocketAddressPortOffset = 2;
    private const int NativeSocketAddressIpv4AddressOffset = 4;
    private const int NativeSocketAddressIpv6FlowInfoOffset = 4;
    private const int NativeSocketAddressIpv6AddressOffset = 8;
    private const int NativeSocketAddressIpv6ScopeIdOffset = 24;
    private const int Ipv4AddressLength = 4;
    private const int Ipv6AddressLength = 16;
    private const int PacketInformationIpv4InterfaceOffset = 0;
    private const int PacketInformationIpv4SourceOffset = 4;
    private const int PacketInformationIpv4AddressOffset = 8;
    private const int PacketInformationIpv6AddressOffset = 0;
    private const int PacketInformationIpv6InterfaceOffset = 16;
    private static readonly int ControlMessageLevelOffset = nuint.Size;
    private static readonly int ControlMessageTypeOffset = nuint.Size + sizeof(int);
    private static readonly nuint ControlMessageHeaderLength = Align((nuint)(nuint.Size + (2 * sizeof(int))));

    internal static uint CreateIpv6FlowLabel(uint flowLabelSeed, QuicConnectionPathIdentity pathIdentity)
    {
        uint flowLabel = (uint)HashCode.Combine(
            flowLabelSeed,
            pathIdentity.RemoteAddress,
            pathIdentity.RemotePort,
            pathIdentity.LocalAddress,
            pathIdentity.LocalPort) & 0x000F_FFFF;

        return flowLabel == 0 ? 1U : flowLabel;
    }

    internal static bool TrySendTo(
        Socket socket,
        ReadOnlySpan<byte> datagram,
        IPEndPoint remoteEndPoint,
        IPAddress localAddress,
        uint flowLabel,
        out int bytesSent)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        ArgumentNullException.ThrowIfNull(localAddress);

        bytesSent = 0;
        if (!OperatingSystem.IsLinux()
            || datagram.IsEmpty
            || !TryGetControlMessageMetadata(localAddress, out int controlLevel, out int controlType, out int packetInformationLength))
        {
            return false;
        }

        nint datagramBuffer = 0;
        nint socketAddressBuffer = 0;
        nint ioVectorBuffer = 0;
        nint controlBuffer = 0;

        try
        {
            datagramBuffer = Marshal.AllocHGlobal(datagram.Length);
            Marshal.Copy(datagram.ToArray(), 0, datagramBuffer, datagram.Length);

            socketAddressBuffer = CreateSocketAddress(remoteEndPoint, flowLabel, out uint socketAddressLength);
            ioVectorBuffer = Marshal.AllocHGlobal(Marshal.SizeOf<NativeIoVector>());
            Marshal.StructureToPtr(
                new NativeIoVector(datagramBuffer, (nuint)datagram.Length),
                ioVectorBuffer,
                fDeleteOld: false);

            controlBuffer = CreatePacketInformationControlMessage(
                localAddress,
                controlLevel,
                controlType,
                packetInformationLength);

            NativeMessageHeader messageHeader = new(
                socketAddressBuffer,
                socketAddressLength,
                ioVectorBuffer,
                ioVectorLength: 1,
                controlBuffer,
                controlLength: ControlMessageSpace((nuint)packetInformationLength),
                flags: 0);

            nint sendResult = SendMessage(socket.Handle, ref messageHeader, flags: 0);
            if (sendResult < 0 || sendResult > int.MaxValue)
            {
                _ = Marshal.GetLastPInvokeError();
                return false;
            }

            bytesSent = (int)sendResult;
            return true;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            FreeIfAllocated(controlBuffer);
            FreeIfAllocated(ioVectorBuffer);
            FreeIfAllocated(socketAddressBuffer);
            FreeIfAllocated(datagramBuffer);
        }
    }

    private static bool TryGetControlMessageMetadata(
        IPAddress localAddress,
        out int controlLevel,
        out int controlType,
        out int packetInformationLength)
    {
        if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            controlLevel = IpProtocolIpv6;
            controlType = Ipv6PacketInformation;
            packetInformationLength = NativePacketInformationV6Length;
            return true;
        }

        if (localAddress.AddressFamily == AddressFamily.InterNetwork)
        {
            controlLevel = IpProtocolIp;
            controlType = IpPacketInformation;
            packetInformationLength = NativePacketInformationLength;
            return true;
        }

        controlLevel = 0;
        controlType = 0;
        packetInformationLength = 0;
        return false;
    }

    private static nint CreateSocketAddress(
        IPEndPoint remoteEndPoint,
        uint flowLabel,
        out uint socketAddressLength)
    {
        if (remoteEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
        {
            nint socketAddressBuffer = Marshal.AllocHGlobal(NativeSocketAddressIn6Length);
            Clear(socketAddressBuffer, NativeSocketAddressIn6Length);
            Marshal.WriteInt16(socketAddressBuffer, NativeSocketAddressFamilyOffset, NativeAddressFamilyInterNetworkV6);
            WriteNetworkPort(socketAddressBuffer, NativeSocketAddressPortOffset, remoteEndPoint.Port);
            // Carry the flow label on the destination address; pktinfo is still used for the source address.
            Marshal.WriteInt32(socketAddressBuffer, NativeSocketAddressIpv6FlowInfoOffset, unchecked((int)flowLabel));
            Marshal.Copy(
                remoteEndPoint.Address.GetAddressBytes(),
                0,
                IntPtr.Add(socketAddressBuffer, NativeSocketAddressIpv6AddressOffset),
                Ipv6AddressLength);
            Marshal.WriteInt32(socketAddressBuffer, NativeSocketAddressIpv6ScopeIdOffset, (int)remoteEndPoint.Address.ScopeId);
            socketAddressLength = NativeSocketAddressIn6Length;
            return socketAddressBuffer;
        }

        if (remoteEndPoint.AddressFamily == AddressFamily.InterNetwork)
        {
            nint socketAddressBuffer = Marshal.AllocHGlobal(NativeSocketAddressInLength);
            Clear(socketAddressBuffer, NativeSocketAddressInLength);
            Marshal.WriteInt16(socketAddressBuffer, NativeSocketAddressFamilyOffset, NativeAddressFamilyInterNetwork);
            WriteNetworkPort(socketAddressBuffer, NativeSocketAddressPortOffset, remoteEndPoint.Port);
            Marshal.Copy(
                remoteEndPoint.Address.GetAddressBytes(),
                0,
                IntPtr.Add(socketAddressBuffer, NativeSocketAddressIpv4AddressOffset),
                Ipv4AddressLength);
            socketAddressLength = NativeSocketAddressInLength;
            return socketAddressBuffer;
        }

        throw new SocketException((int)SocketError.AddressFamilyNotSupported);
    }

    private static nint CreatePacketInformationControlMessage(
        IPAddress localAddress,
        int controlLevel,
        int controlType,
        int packetInformationLength)
    {
        nuint controlLength = ControlMessageSpace((nuint)packetInformationLength);
        nint controlBuffer = Marshal.AllocHGlobal((int)controlLength);
        Clear(controlBuffer, (int)controlLength);

        Marshal.WriteIntPtr(controlBuffer, 0, (nint)ControlMessageLength((nuint)packetInformationLength));
        Marshal.WriteInt32(controlBuffer, ControlMessageLevelOffset, controlLevel);
        Marshal.WriteInt32(controlBuffer, ControlMessageTypeOffset, controlType);

        nint packetInformationBuffer = IntPtr.Add(controlBuffer, (int)ControlMessageHeaderLength);
        byte[] localAddressBytes = localAddress.GetAddressBytes();
        if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
        {
            Marshal.Copy(localAddressBytes, 0, IntPtr.Add(packetInformationBuffer, PacketInformationIpv6AddressOffset), Ipv6AddressLength);
            Marshal.WriteInt32(packetInformationBuffer, PacketInformationIpv6InterfaceOffset, 0);
        }
        else
        {
            Marshal.WriteInt32(packetInformationBuffer, PacketInformationIpv4InterfaceOffset, 0);
            Marshal.Copy(
                localAddressBytes,
                0,
                IntPtr.Add(packetInformationBuffer, PacketInformationIpv4SourceOffset),
                Ipv4AddressLength);
            Marshal.Copy(
                localAddressBytes,
                0,
                IntPtr.Add(packetInformationBuffer, PacketInformationIpv4AddressOffset),
                Ipv4AddressLength);
        }

        return controlBuffer;
    }

    private static void Clear(nint buffer, int length)
    {
        byte[] empty = new byte[length];
        Marshal.Copy(empty, 0, buffer, length);
    }

    private static void WriteNetworkPort(nint buffer, int offset, int port)
    {
        short networkPort = IPAddress.HostToNetworkOrder((short)port);
        Marshal.WriteInt16(buffer, offset, networkPort);
    }

    private static nuint ControlMessageLength(nuint dataLength)
    {
        return ControlMessageHeaderLength + dataLength;
    }

    private static nuint ControlMessageSpace(nuint dataLength)
    {
        return ControlMessageHeaderLength + Align(dataLength);
    }

    private static nuint Align(nuint length)
    {
        nuint alignment = (nuint)nint.Size;
        return (length + alignment - 1) & ~(alignment - 1);
    }

    private static void FreeIfAllocated(nint buffer)
    {
        if (buffer != 0)
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [LibraryImport("libc.so.6", EntryPoint = "sendmsg", SetLastError = true)]
    private static partial nint SendMessage(nint socket, ref NativeMessageHeader messageHeader, int flags);

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeIoVector
    {
        internal NativeIoVector(nint @base, nuint length)
        {
            Base = @base;
            Length = length;
        }

        internal readonly nint Base;
        internal readonly nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeMessageHeader
    {
        internal NativeMessageHeader(
            nint name,
            uint nameLength,
            nint ioVector,
            nuint ioVectorLength,
            nint control,
            nuint controlLength,
            int flags)
        {
            Name = name;
            NameLength = nameLength;
            IoVector = ioVector;
            IoVectorLength = ioVectorLength;
            Control = control;
            ControlLength = controlLength;
            Flags = flags;
        }

        internal readonly nint Name;
        internal readonly uint NameLength;
        internal readonly nint IoVector;
        internal readonly nuint IoVectorLength;
        internal readonly nint Control;
        internal readonly nuint ControlLength;
        internal readonly int Flags;
    }
}
