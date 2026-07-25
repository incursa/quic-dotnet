// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Incursa.Quic;

internal static partial class QuicSocketUdpSegmentation
{
    internal const int SegmentSize = QuicConnectionRuntime.HostedApplicationDatagramBatchSegmentSize;
    internal const int MaximumSegmentsPerSend = QuicConnectionRuntime.HostedApplicationDatagramBatchCapacity;
    internal const int MinimumSegmentsPerSend = 2;

    private const int WindowsUdpProtocolLevel = 17;
    private const int WindowsUdpSendMessageSizeOption = 2;

    internal static bool TryEnable(Socket socket)
        => TryConfigure(socket, SegmentSize);

    internal static bool TryDisable(Socket socket)
        => TryConfigure(socket, segmentSize: 0);

    internal static
        QuicApplicationDatagramBatchTransportCapabilityStatus
        ClassifyCapability(
            Socket socket,
            bool enabled,
            bool disabledByCustomSender = false)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (disabledByCustomSender)
        {
            return QuicApplicationDatagramBatchTransportCapabilityStatus
                .DisabledByCustomSender;
        }

        if (!OperatingSystem.IsWindows())
        {
            return QuicApplicationDatagramBatchTransportCapabilityStatus
                .UnsupportedPlatform;
        }

        if (socket.AddressFamily
            is not (AddressFamily.InterNetwork
                or AddressFamily.InterNetworkV6))
        {
            return QuicApplicationDatagramBatchTransportCapabilityStatus
                .UnsupportedAddressFamily;
        }

        return enabled
            ? QuicApplicationDatagramBatchTransportCapabilityStatus
                .WindowsUdpSendMessageSize
            : QuicApplicationDatagramBatchTransportCapabilityStatus
                .ProbeFailed;
    }

    private static bool TryConfigure(Socket socket, int segmentSize)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (!OperatingSystem.IsWindows()
            || socket.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return false;
        }

        try
        {
            return SetSocketOption(
                socket.SafeHandle,
                WindowsUdpProtocolLevel,
                WindowsUdpSendMessageSizeOption,
                ref segmentSize,
                sizeof(int)) == 0;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
    }

    internal static int Send(
        Socket socket,
        ReadOnlySpan<byte> contiguousPayload,
        int segmentCount,
        SocketAddress destination)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(destination);
        if (segmentCount is < MinimumSegmentsPerSend or > MaximumSegmentsPerSend
            || contiguousPayload.Length != checked(segmentCount * SegmentSize))
        {
            throw new ArgumentOutOfRangeException(nameof(segmentCount));
        }

        int sentBytes = socket.SendTo(contiguousPayload, SocketFlags.None, destination);
        if (sentBytes != contiguousPayload.Length)
        {
            throw new IOException("Failed to send the complete segmented QUIC datagram batch.");
        }

        return sentBytes;
    }

    [LibraryImport("Ws2_32.dll", EntryPoint = "setsockopt", SetLastError = true)]
    private static partial int SetSocketOption(
        SafeSocketHandle socket,
        int level,
        int optionName,
        ref int optionValue,
        int optionLength);
}
