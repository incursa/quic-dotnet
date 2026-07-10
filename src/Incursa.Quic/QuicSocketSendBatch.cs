// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace Incursa.Quic;

/// <summary>
/// Sends UDP datagrams in a batch, using <c>sendmmsg</c> on Linux when it is available and a
/// managed <see cref="Socket.SendTo(ReadOnlySpan{byte}, SocketFlags, SocketAddress)" /> fallback
/// everywhere else.
/// </summary>
internal static partial class QuicSocketSendBatch
{
    private const string LinuxLibC = "libc.so.6";

    private static readonly bool s_isNativeSendMmsgSupported = OperatingSystem.IsLinux()
        && TryDetectNativeSendMmsgSupport();

    /// <summary>
    /// Gets whether the current process can call the Linux native batch send primitive.
    /// </summary>
    internal static bool IsNativeSendMmsgSupported => s_isNativeSendMmsgSupported;

    /// <summary>
    /// Sends a batch of UDP datagrams while preserving each datagram payload, destination, and
    /// batch order.
    /// </summary>
    internal static QuicSocketSendBatchResult Send(Socket socket, ReadOnlySpan<QuicSocketSendBatchMessage> messages)
    {
        ArgumentNullException.ThrowIfNull(socket);

        if (messages.IsEmpty)
        {
            return new QuicSocketSendBatchResult(sentMessages: 0, sentBytes: 0, usedNativeSendMmsg: false);
        }

        if (!s_isNativeSendMmsgSupported)
        {
            return SendWithRepeatedSendTo(socket, messages);
        }

        try
        {
            return SendWithNativeSendMmsg(socket, messages);
        }
        catch (DllNotFoundException)
        {
            return SendWithRepeatedSendTo(socket, messages);
        }
        catch (EntryPointNotFoundException)
        {
            return SendWithRepeatedSendTo(socket, messages);
        }
    }

    private static QuicSocketSendBatchResult SendWithRepeatedSendTo(
        Socket socket,
        ReadOnlySpan<QuicSocketSendBatchMessage> messages)
    {
        int sentMessages = 0;
        int sentBytes = 0;

        foreach (QuicSocketSendBatchMessage message in messages)
        {
            if (!TrySendSingleDatagram(socket, message, ref sentBytes))
            {
                break;
            }

            sentMessages++;
        }

        return new QuicSocketSendBatchResult(sentMessages, sentBytes, usedNativeSendMmsg: false);
    }

    private static bool TrySendSingleDatagram(
        Socket socket,
        QuicSocketSendBatchMessage message,
        ref int sentBytes)
    {
        while (true)
        {
            try
            {
                sentBytes = checked(sentBytes + socket.SendTo(message.Payload.Span, SocketFlags.None, message.Destination));
                return true;
            }
            catch (SocketException exception) when (exception.SocketErrorCode == SocketError.Interrupted)
            {
                return TrySendSingleDatagram(socket, message, ref sentBytes);
            }
            catch (SocketException exception) when (
                exception.SocketErrorCode == SocketError.WouldBlock
                || exception.SocketErrorCode == SocketError.TryAgain)
            {
                return false;
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

    private static unsafe QuicSocketSendBatchResult SendWithNativeSendMmsg(
        Socket socket,
        ReadOnlySpan<QuicSocketSendBatchMessage> messages)
    {
        nint socketHandle = socket.Handle;
        int messageCount = messages.Length;
        NativeMmsghdr[] nativeMessages = new NativeMmsghdr[messageCount];
        NativeIovec[] nativeIovecs = new NativeIovec[messageCount];
        nint[] payloadBuffers = new nint[messageCount];
        nint[] destinationBuffers = new nint[messageCount];

        try
        {
            for (int index = 0; index < messageCount; index++)
            {
                ReadOnlySpan<byte> payload = messages[index].Payload.Span;
                nint payloadBuffer = AllocateBuffer(payload);
                nint destinationBuffer = AllocateSocketAddressBuffer(messages[index].Destination);

                payloadBuffers[index] = payloadBuffer;
                destinationBuffers[index] = destinationBuffer;
                nativeIovecs[index] = new NativeIovec
                {
                    Base = payloadBuffer,
                    Length = (nuint)payload.Length,
                };
                nativeMessages[index] = new NativeMmsghdr
                {
                    MessageHeader = new NativeMsghdr
                    {
                        Name = destinationBuffer,
                        NameLength = (uint)messages[index].Destination.Size,
                        IoVector = null,
                        IoVectorLength = 1,
                        Control = 0,
                        ControlLength = 0,
                        Flags = 0,
                    },
                    MessageLength = 0,
                };
            }

            fixed (NativeMmsghdr* nativeMessagesPtr = nativeMessages)
            fixed (NativeIovec* nativeIovecsPtr = nativeIovecs)
            {
                for (int index = 0; index < messageCount; index++)
                {
                    nativeMessagesPtr[index].MessageHeader.IoVector = nativeIovecsPtr + index;
                }

                int sentMessages = 0;
                int sentBytes = 0;

                while (sentMessages < messageCount)
                {
                    int sendResult = SendMMsg(
                        socketHandle,
                        nativeMessagesPtr + sentMessages,
                        (uint)(messageCount - sentMessages),
                        flags: 0);

                    if (sendResult > 0)
                    {
                        for (int index = 0; index < sendResult; index++)
                        {
                            sentBytes = checked(sentBytes + (int)(nativeMessagesPtr[sentMessages + index].MessageLength));
                        }

                        sentMessages += sendResult;
                        break;
                    }

                    if (sendResult == 0)
                    {
                        break;
                    }

                    int error = Marshal.GetLastPInvokeError();
                    if (error == (int)SocketError.Interrupted)
                    {
                        continue;
                    }

                    break;
                }

                return new QuicSocketSendBatchResult(sentMessages, sentBytes, usedNativeSendMmsg: true);
            }
        }
        catch (ObjectDisposedException)
        {
            return new QuicSocketSendBatchResult(sentMessages: 0, sentBytes: 0, usedNativeSendMmsg: true);
        }
        finally
        {
            for (int index = 0; index < messageCount; index++)
            {
                FreeIfAllocated(destinationBuffers[index]);
                FreeIfAllocated(payloadBuffers[index]);
            }
        }
    }

    private static bool TryDetectNativeSendMmsgSupport()
    {
        foreach (string libraryName in new[] { LinuxLibC, "libc.so" })
        {
            if (!NativeLibrary.TryLoad(libraryName, out nint libraryHandle))
            {
                continue;
            }

            try
            {
                if (NativeLibrary.TryGetExport(libraryHandle, "sendmmsg", out _))
                {
                    return true;
                }
            }
            finally
            {
                NativeLibrary.Free(libraryHandle);
            }
        }

        return false;
    }

    private static unsafe nint AllocateBuffer(ReadOnlySpan<byte> source)
    {
        if (source.IsEmpty)
        {
            return 0;
        }

        nint buffer = Marshal.AllocHGlobal(source.Length);
        source.CopyTo(new Span<byte>((void*)buffer, source.Length));
        return buffer;
    }

    private static unsafe nint AllocateSocketAddressBuffer(SocketAddress socketAddress)
    {
        int length = socketAddress.Size;
        if (length <= 0)
        {
            return 0;
        }

        nint buffer = Marshal.AllocHGlobal(length);
        Span<byte> destination = new((void*)buffer, length);
        for (int index = 0; index < length; index++)
        {
            destination[index] = socketAddress[index];
        }

        return buffer;
    }

    private static void FreeIfAllocated(nint buffer)
    {
        if (buffer != 0)
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [LibraryImport(LinuxLibC, EntryPoint = "sendmmsg", SetLastError = true)]
    private static unsafe partial int SendMMsg(nint socket, NativeMmsghdr* messageVector, uint vectorLength, int flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeIovec
    {
        internal nint Base;
        internal nuint Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct NativeMsghdr
    {
        internal nint Name;
        internal uint NameLength;
        internal NativeIovec* IoVector;
        internal nuint IoVectorLength;
        internal nint Control;
        internal nuint ControlLength;
        internal int Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeMmsghdr
    {
        internal NativeMsghdr MessageHeader;
        internal uint MessageLength;
    }
}

/// <summary>
/// Represents one datagram entry in a batch send operation.
/// </summary>
internal readonly struct QuicSocketSendBatchMessage
{
    /// <summary>
    /// Initializes a new batch entry.
    /// </summary>
    internal QuicSocketSendBatchMessage(ReadOnlyMemory<byte> payload, SocketAddress destination)
    {
        Payload = payload;
        Destination = destination ?? throw new ArgumentNullException(nameof(destination));
    }

    /// <summary>
    /// Gets the payload to send.
    /// </summary>
    internal ReadOnlyMemory<byte> Payload { get; }

    /// <summary>
    /// Gets the destination socket address for the datagram.
    /// </summary>
    internal SocketAddress Destination { get; }
}

/// <summary>
/// Describes the outcome of a batch send attempt.
/// </summary>
internal readonly struct QuicSocketSendBatchResult
{
    /// <summary>
    /// Initializes a new result.
    /// </summary>
    internal QuicSocketSendBatchResult(int sentMessages, int sentBytes, bool usedNativeSendMmsg)
    {
        SentMessages = sentMessages;
        SentBytes = sentBytes;
        UsedNativeSendMmsg = usedNativeSendMmsg;
    }

    /// <summary>
    /// Gets the number of datagrams the socket accepted.
    /// </summary>
    internal int SentMessages { get; }

    /// <summary>
    /// Gets the total payload bytes accepted by the socket.
    /// </summary>
    internal int SentBytes { get; }

    /// <summary>
    /// Gets whether the Linux native batch primitive was used.
    /// </summary>
    internal bool UsedNativeSendMmsg { get; }
}
