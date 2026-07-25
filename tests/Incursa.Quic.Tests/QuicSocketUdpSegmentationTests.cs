// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

public sealed class QuicSocketUdpSegmentationTests
{
    [Fact]
    public void ClassifyCapability_CustomSenderRemainsAuthoritative()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        Assert.Equal(
            QuicApplicationDatagramBatchTransportCapabilityStatus.DisabledByCustomSender,
            QuicSocketUdpSegmentation.ClassifyCapability(
                socket,
                enabled: true,
                disabledByCustomSender: true));
    }

    [Fact]
    public void ClassifyCapability_DisabledProbeUsesBoundedPlatformStatus()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        QuicApplicationDatagramBatchTransportCapabilityStatus expected =
            OperatingSystem.IsWindows()
                ? QuicApplicationDatagramBatchTransportCapabilityStatus.ProbeFailed
                : QuicApplicationDatagramBatchTransportCapabilityStatus.UnsupportedPlatform;

        Assert.Equal(
            expected,
            QuicSocketUdpSegmentation.ClassifyCapability(socket, enabled: false));
    }

    [Fact]
    public void ClassifyCapability_EnabledProbeUsesBoundedPlatformStatus()
    {
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

        QuicApplicationDatagramBatchTransportCapabilityStatus expected =
            OperatingSystem.IsWindows()
                ? QuicApplicationDatagramBatchTransportCapabilityStatus.WindowsUdpSendMessageSize
                : QuicApplicationDatagramBatchTransportCapabilityStatus.UnsupportedPlatform;

        Assert.Equal(
            expected,
            QuicSocketUdpSegmentation.ClassifyCapability(socket, enabled: true));
    }

    [Theory]
    [InlineData(1200)]
    [InlineData(1452)]
    [InlineData(1472)]
    public void EnabledSocketPreservesOrdinarySingleDatagrams(int datagramLength)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using Socket receiver = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        receiver.ReceiveTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;

        using Socket sender = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sender.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Assert.True(QuicSocketUdpSegmentation.TryEnable(sender));

        byte[] payload = Enumerable.Range(0, datagramLength)
            .Select(static value => unchecked((byte)value))
            .ToArray();
        Assert.Equal(
            datagramLength,
            sender.SendTo(payload, SocketFlags.None, ((IPEndPoint)receiver.LocalEndPoint!).Serialize()));

        byte[] receiveBuffer = new byte[2048];
        int received = receiver.Receive(receiveBuffer, SocketFlags.None);
        Assert.Equal(datagramLength, received);
        Assert.Equal(payload, receiveBuffer.AsSpan(0, received).ToArray());
    }

    [Fact]
    public void Send_PreservesSegmentLengthsContentsAndOrdering()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using Socket receiver = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        receiver.ReceiveTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;

        using Socket sender = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sender.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Assert.True(QuicSocketUdpSegmentation.TryEnable(sender));

        byte[] payload = new byte[2 * QuicSocketUdpSegmentation.SegmentSize];
        payload.AsSpan(0, QuicSocketUdpSegmentation.SegmentSize).Fill(0x11);
        payload.AsSpan(QuicSocketUdpSegmentation.SegmentSize).Fill(0x22);

        int sent = QuicSocketUdpSegmentation.Send(
            sender,
            payload,
            segmentCount: 2,
            ((IPEndPoint)receiver.LocalEndPoint!).Serialize());

        Assert.Equal(payload.Length, sent);
        byte[] receiveBuffer = new byte[2048];
        for (int index = 0; index < 2; index++)
        {
            int received = receiver.Receive(receiveBuffer, SocketFlags.None);
            Assert.Equal(QuicSocketUdpSegmentation.SegmentSize, received);
            Assert.All(
                receiveBuffer.AsSpan(0, received).ToArray(),
                value => Assert.Equal(index == 0 ? (byte)0x11 : (byte)0x22, value));
        }
    }

    [Fact]
    public void TryDisableRestoresOrdinaryDatagramSubmission()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using Socket receiver = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        receiver.ReceiveTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;

        using Socket sender = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        sender.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        Assert.True(QuicSocketUdpSegmentation.TryEnable(sender));
        Assert.True(QuicSocketUdpSegmentation.TryDisable(sender));

        byte[] payload = new byte[QuicSocketUdpSegmentation.SegmentSize];
        payload.AsSpan().Fill(0x37);
        Assert.Equal(
            payload.Length,
            sender.SendTo(payload, SocketFlags.None, ((IPEndPoint)receiver.LocalEndPoint!).Serialize()));

        byte[] receiveBuffer = new byte[payload.Length + 1];
        int received = receiver.Receive(receiveBuffer, SocketFlags.None);
        Assert.Equal(payload.Length, received);
        Assert.Equal(payload, receiveBuffer.AsSpan(0, received).ToArray());
    }
}
