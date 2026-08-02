// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionRuntimePublicationTests
{
    [Fact]
    public async Task CaptureQueuedApplicationSendPolicySnapshot_DoesNotReadMutableAckRangesAcrossThreads()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "127.0.0.1",
            LocalAddress: "127.0.0.1",
            RemotePort: 443,
            LocalPort: 50_000);

        Assert.True(runtime.InitializeActivePath(pathIdentity, payloadBytes: 1200, nowTicks: 1));
        QuicSenderFlowController flowController = runtime.SendRuntime.FlowController;
        flowController.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 0,
            ackEliciting: true,
            receivedAtMicros: 1);

        using CancellationTokenSource cancellationSource = new();
        Task publisher = Task.Run(() =>
        {
            ulong packetNumber = 2;
            while (!cancellationSource.IsCancellationRequested)
            {
                flowController.RecordIncomingPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    packetNumber,
                    ackEliciting: true,
                    receivedAtMicros: packetNumber);
                packetNumber += 2;
            }
        });

        try
        {
            for (int iteration = 0; iteration < 100_000; iteration++)
            {
                QuicSendPolicySnapshot snapshot =
                    runtime.CaptureQueuedApplicationSendPolicySnapshot();
                Assert.True(snapshot.MaximumApplicationPayloadBytes > 0);
            }
        }
        finally
        {
            cancellationSource.Cancel();
            await publisher.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    [Fact]
    public async Task CaptureQueuedApplicationSendPolicySnapshot_DoesNotReadMutableActivePathAcrossThreads()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "127.0.0.1",
            LocalAddress: "127.0.0.1",
            RemotePort: 443,
            LocalPort: 50_000);

        Assert.True(runtime.InitializeActivePath(pathIdentity, payloadBytes: 1200, nowTicks: 1));

        using CancellationTokenSource cancellationSource = new();
        Task publisher = Task.Run(() =>
        {
            long nowTicks = 2;
            while (!cancellationSource.IsCancellationRequested)
            {
                Assert.True(runtime.InitializeActivePath(pathIdentity, payloadBytes: 1200, nowTicks++));
            }
        });

        try
        {
            for (int iteration = 0; iteration < 25_000; iteration++)
            {
                QuicSendPolicySnapshot snapshot =
                    runtime.CaptureQueuedApplicationSendPolicySnapshot();
                Assert.True(snapshot.MaximumApplicationPayloadBytes > 0);
            }
        }
        finally
        {
            cancellationSource.Cancel();
            await publisher.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }

    [Fact]
    public async Task OpenOutboundStream_DoesNotReadMutableActivePathAcrossThreads()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionPathIdentity pathIdentity = new(
            RemoteAddress: "127.0.0.1",
            LocalAddress: "127.0.0.1",
            RemotePort: 443,
            LocalPort: 50_000);

        Assert.True(runtime.InitializeActivePath(pathIdentity, payloadBytes: 1200, nowTicks: 1));
        runtime.SetPhaseForTesting(QuicConnectionPhase.Active);

        using CancellationTokenSource cancellationSource = new();
        Task publisher = Task.Run(() =>
        {
            long nowTicks = 2;
            while (!cancellationSource.IsCancellationRequested)
            {
                Assert.True(runtime.InitializeActivePath(pathIdentity, payloadBytes: 1200, nowTicks++));
            }
        });

        try
        {
            for (int iteration = 0; iteration < 25_000; iteration++)
            {
                Assert.Throws<ArgumentOutOfRangeException>(() =>
                    runtime.OpenOutboundStreamAsync(unchecked((QuicStreamType)int.MaxValue)));
            }
        }
        finally
        {
            cancellationSource.Cancel();
            await publisher.WaitAsync(TimeSpan.FromSeconds(10));
        }
    }
}
