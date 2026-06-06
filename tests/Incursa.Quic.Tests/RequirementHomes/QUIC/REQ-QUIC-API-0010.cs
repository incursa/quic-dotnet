// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-API-0010">On the supported active loopback path, send-capable QuicStream facades MUST support immediate 1-RTT writes, best-effort graceful write completion through stream disposal, peer read-side byte delivery, and matching EOF observation without implying broader stream parity.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-API-0010")]
public sealed class REQ_QUIC_API_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackWriteAndDisposeCompletion_DeliversBytesAndPeerEof()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] payload = [0x10, 0x20, 0x30, 0x40, 0x50];
        await pair.ClientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] receiveBuffer = new byte[payload.Length];
        int bytesRead = await ReadWithDiagnosticsAsync(pair, receiveBuffer, payload.Length);
        Assert.Equal(payload.Length, bytesRead);
        Assert.True(payload.AsSpan().SequenceEqual(receiveBuffer));

        Assert.Equal(0, await pair.ServerStream.ReadAsync(receiveBuffer, 0, receiveBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [Requirement("REQ-QUIC-RFC9000-S2P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task SupportedLoopbackWrite_EncodesApplicationBytesInAStreamFrame()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] payload = [0x10, 0x20, 0x30, 0x40];
        await pair.ClientStream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));
        QuicConnectionRuntime senderRuntime = GetRuntime(pair.ClientConnection);
        QuicConnectionSentPacket? dataPacket = null;
        for (int attempt = 0; attempt < 100 && dataPacket is null; attempt++)
        {
            try
            {
                dataPacket = senderRuntime.SendRuntime.SentPackets.Values.ToArray().FirstOrDefault(packet =>
                    packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                    && TryFindStreamFrame(
                        packet.PlaintextPayload.Span,
                        (ulong)pair.ClientStream.Id,
                        offset: 0,
                        streamDataLength: payload.Length,
                        fin: false,
                        out _));
            }
            catch (InvalidOperationException)
            {
                dataPacket = null;
            }
            catch (ArgumentException)
            {
                dataPacket = null;
            }

            if (dataPacket is null)
            {
                await Task.Delay(20);
            }
        }

        Assert.NotNull(dataPacket);

        await pair.ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-API-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DelayedStreamWritesKeepTheirOwnedPayloadStableUntilTheQueuedSendFlushes()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 96,
            localBidirectionalSendLimit: 96);
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] originalPayload = [0x10, 0x20, 0x30, 0x40, 0x50];
        byte[] mutatedPayload = originalPayload.ToArray();

        await stream.WriteAsync(mutatedPayload, 0, mutatedPayload.Length).WaitAsync(TimeSpan.FromSeconds(5));

        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        mutatedPayload[0] = 0xFF;
        mutatedPayload[1] = 0xEE;

        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);
        QuicConnectionTransitionResult flushResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);
        outboundEffects.AddRange(flushResult.Effects);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] openedPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        Assert.True(TryFindStreamFrame(
            openedPayload,
            (ulong)stream.Id,
            offset: 0,
            streamDataLength: originalPayload.Length,
            fin: false,
            out QuicStreamFrame frame));
        Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
        Assert.True(frame.StreamData.SequenceEqual(originalPayload));
        Assert.False(frame.StreamData.SequenceEqual(mutatedPayload));
    }

    [Fact]
    [Requirement("REQ-QUIC-API-0010")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task DelayedStreamWritesKeepTheirOwnedPayloadStableThroughLossAndRetransmission()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 96,
            localBidirectionalSendLimit: 96);
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] originalPayload = [0x61, 0x62, 0x63, 0x64, 0x65];
        byte[] mutatedPayload = originalPayload.ToArray();

        await stream.WriteAsync(mutatedPayload, 0, mutatedPayload.Length).WaitAsync(TimeSpan.FromSeconds(5));

        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        mutatedPayload[0] = 0xFF;
        mutatedPayload[1] = 0xEE;

        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);
        QuicConnectionTransitionResult flushResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);
        outboundEffects.AddRange(flushResult.Effects);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> originalPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);

        byte[] openedPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        Assert.True(TryFindStreamFrame(
            openedPayload,
            (ulong)stream.Id,
            offset: 0,
            streamDataLength: originalPayload.Length,
            fin: false,
            out QuicStreamFrame originalFrame));
        Assert.True(originalFrame.StreamData.SequenceEqual(originalPayload));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            originalPacket.Key.PacketNumberSpace,
            originalPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        List<QuicConnectionEffect>? retransmissionEffects = [];
        Assert.True(QuicS13AckPiggybackTestSupport.InvokeTryFlushPendingRetransmissions(
            runtime,
            QuicPacketNumberSpace.ApplicationData,
            nowTicks: dueTicks.Value + 1,
            probePacket: false,
            ref retransmissionEffects));

        QuicConnectionSendDatagramEffect retransmissionSend = Assert.Single(
            retransmissionEffects!.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> retransmittedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, retransmissionSend.Datagram);

        Assert.NotEqual(originalPacket.Key.PacketNumber, retransmittedPacket.Key.PacketNumber);

        byte[] retransmittedPlaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, retransmissionSend);
        Assert.True(TryFindStreamFrame(
            retransmittedPlaintext,
            (ulong)stream.Id,
            offset: 0,
            streamDataLength: originalPayload.Length,
            fin: false,
            out QuicStreamFrame retransmittedFrame));
        Assert.True(retransmittedFrame.StreamData.SequenceEqual(originalPayload));
        Assert.False(retransmittedFrame.StreamData.SequenceEqual(mutatedPayload));
    }

    [Fact]
    [Requirement("REQ-QUIC-API-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task OversizedQueuedStreamWriteFlushesBoundedFragmentsPerLocalTransition()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 65_536,
            localBidirectionalSendLimit: 65_536);
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] payload = Enumerable.Range(0, 8192).Select(static index => (byte)(index % 251)).ToArray();
        await stream.WriteAsync(payload, 0, payload.Length).WaitAsync(TimeSpan.FromSeconds(5));

        QuicConnectionSendDatagramEffect[] sendEffects = outboundEffects
            .OfType<QuicConnectionSendDatagramEffect>()
            .ToArray();
        Assert.Equal(4, sendEffects.Length);

        byte[] openedPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffects[0]);
        Assert.True(TryFindAnyStreamFrame(openedPayload, (ulong)stream.Id, out QuicStreamFrame frame));
        Assert.Equal(0UL, frame.Offset);
        Assert.InRange(frame.StreamDataLength, 1, payload.Length - 1);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [Requirement("REQ-QUIC-API-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task FlowControlBlockedStreamWriteResumesAfterPeerRaisesStreamCredit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 4096,
            connectionSendLimit: 4096,
            localBidirectionalSendLimit: 64,
            localBidirectionalReceiveLimit: 2048);
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        byte[] payload = Enumerable.Range(0, 128).Select(static index => (byte)(index % 251)).ToArray();
        Task writeTask = stream.WriteAsync(payload, 0, payload.Length);
        await Task.Delay(150);
        Assert.False(writeTask.IsCompleted, "The write should still be waiting for peer stream credit.");

        QuicHandshakeFlowCoordinator peerCoordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        byte[] maxStreamDataPayload = QuicFrameTestData.BuildMaxStreamDataFrame(
            new QuicMaxStreamDataFrame((ulong)stream.Id, (ulong)payload.Length));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            maxStreamDataPayload,
            minimumPacketNumberExclusive: 5,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out ulong peerPacketNumber,
            out byte[] peerPacket));
        Assert.Equal(6UL, peerPacketNumber);

        QuicConnectionTransitionResult peerResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                peerPacket),
            nowTicks: 10);
        Assert.True(peerResult.StateChanged, DescribeStream(stream));

        QuicConnectionSendDatagramEffect matchedSendEffect = Assert.Single(
            peerResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => PacketContainsStreamFrame(
                effect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                runtime.CurrentPeerDestinationConnectionId.Span,
                (ulong)stream.Id,
                offset: 0,
                streamDataLength: payload.Length,
                fin: false));

        QuicHandshakeFlowCoordinator outgoingCoordinator = new(runtime.CurrentPeerDestinationConnectionId);
        Assert.True(outgoingCoordinator.TryOpenProtectedApplicationDataPacket(
            matchedSendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out _));

        Assert.True(TryFindStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            (ulong)stream.Id,
            offset: 0,
            streamDataLength: payload.Length,
            fin: false,
            out QuicStreamFrame frame));
        Assert.True(frame.StreamData.SequenceEqual(payload));

        await writeTask.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AcceptedBidirectionalStreamCanReturnResponseBytesAfterTheRequesterCompletesOnlyItsWriteSide()
    {
        // Regression from the local interop-runner handshake lane on 2026-04-20:
        // the client must finish its HTTP/0.9 request write side while keeping the read side open
        // so the peer can send the response back on the same bidirectional stream.
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] request = Encoding.ASCII.GetBytes("GET /captured-interop.txt\r\n");
        byte[] response = Encoding.ASCII.GetBytes("captured interop response");

        await pair.ClientStream.WriteAsync(request, 0, request.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] requestBuffer = new byte[request.Length];
        int requestBytesRead = await ReadWithDiagnosticsAsync(pair, requestBuffer, request.Length);
        Assert.Equal(request.Length, requestBytesRead);
        Assert.True(request.AsSpan().SequenceEqual(requestBuffer));
        Assert.Equal(0, await pair.ServerStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));

        const int responseChunkBytes = 64;
        for (int offset = 0; offset < response.Length; offset += responseChunkBytes)
        {
            int bytesToWrite = Math.Min(responseChunkBytes, response.Length - offset);
            await pair.ServerStream.WriteAsync(response, offset, bytesToWrite).WaitAsync(TimeSpan.FromSeconds(5));
        }

        await pair.ServerStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ServerStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await pair.ClientStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));
        Assert.Equal(0, await pair.ClientStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ClientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task FollowupReadPendingBeforePeerFin_CompletesWithEofWhenThePeerClosesLater()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-212428010-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 22/50 sent "GET /vibrant-arctic-vga\r\n" and then timed out waiting for more bytes or EOF.
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go first sent STREAM data length 1024 at offset 0, then later retransmitted a FIN-only STREAM
        //     frame at offset 1024 after the client had already consumed the response bytes.
        // The public stream facade must surface that later peer FIN to a pending follow-up ReadAsync rather than
        // leaving the read blocked after the body bytes have already been delivered.
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        byte[] request = Encoding.ASCII.GetBytes("GET /vibrant-arctic-vga\r\n");
        byte[] response = Enumerable.Range(0, 1024).Select(static i => (byte)(i % 251)).ToArray();

        await pair.ClientStream.WriteAsync(request, 0, request.Length).WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ClientStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        byte[] requestBuffer = new byte[request.Length];
        int requestBytesRead = await ReadWithDiagnosticsAsync(pair, requestBuffer, request.Length);
        Assert.Equal(request.Length, requestBytesRead);
        Assert.True(request.AsSpan().SequenceEqual(requestBuffer));
        Assert.Equal(0, await pair.ServerStream.ReadAsync(new byte[1], 0, 1).WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ServerStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));

        await pair.ServerStream.WriteAsync(response, 0, response.Length).WaitAsync(TimeSpan.FromSeconds(5));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await pair.ClientStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));

        Task<int> pendingFollowupRead = pair.ClientStream.ReadAsync(new byte[1], 0, 1);
        await Task.Delay(150);
        Assert.False(pendingFollowupRead.IsCompleted, "The follow-up read should still be waiting before the peer sends FIN.");

        await pair.ServerStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await pair.ServerStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, await pendingFollowupRead.WaitAsync(TimeSpan.FromSeconds(5)));
        await pair.ClientStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeIngressReplay_DeliversBodyThenSurfacesDelayedPeerFinToTheSamePendingRead()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-212428010-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 22/50 sent "GET /vibrant-arctic-vga\r\n" and then timed out waiting for more bytes or EOF.
        //   runner-logs\quic-go_chrome\handshakeloss\server\log.txt:
        //     quic-go sent STREAM stream_id=0 offset=0 length=1024, then later retransmitted a FIN-only STREAM
        //     frame at offset 1024 after the client had already advanced its flow-control credit on that stream.
        // This replay drives the actual protected 1-RTT ingress path rather than the local loopback writer.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 4096,
            localBidirectionalReceiveLimit: 2048);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            runtime.Transition(connectionEvent);
            return true;
        });

        await using QuicStream requestStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, requestStream.Id);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator peerCoordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        byte[] response = Enumerable.Range(0, 1024).Select(static index => (byte)(index % 251)).ToArray();

        byte[] responsePayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: (ulong)requestStream.Id,
            streamData: response,
            offset: 0);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            responsePayload,
            minimumPacketNumberExclusive: 5,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out ulong responsePacketNumber,
            out byte[] responsePacket));
        Assert.Equal(6UL, responsePacketNumber);

        QuicConnectionTransitionResult responseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                responsePacket),
            nowTicks: 10);
        Assert.True(responseResult.StateChanged, DescribeStream(requestStream));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await requestStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));

        Task<int> pendingFollowupRead = requestStream.ReadAsync(new byte[1], 0, 1);
        await Task.Delay(150);
        Assert.False(
            pendingFollowupRead.IsCompleted,
            $"The follow-up read should still be waiting before the delayed FIN arrives. {DescribeStream(requestStream)}");

        byte[] responseFinPayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: (ulong)requestStream.Id,
            streamData: [],
            offset: (ulong)response.Length);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            responseFinPayload,
            minimumPacketNumberExclusive: 9,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out ulong responseFinPacketNumber,
            out byte[] responseFinPacket));
        Assert.Equal(10UL, responseFinPacketNumber);

        QuicConnectionTransitionResult responseFinResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                runtime.ActivePath.Value.Identity,
                responseFinPacket),
            nowTicks: 11);
        Assert.True(responseFinResult.StateChanged, DescribeStream(requestStream));

        Assert.Equal(0, await pendingFollowupRead.WaitAsync(TimeSpan.FromSeconds(5)));
        await requestStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0047")]
    [Requirement("REQ-QUIC-RFC9000-0048")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RuntimeIngressReplay_GapFillingRetransmissionWakesPendingOrderedRead()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\.artifacts\interop-runner\all-upstream-nonhandshake-local\client\20260519-104925879-client-chrome
        //   runner-logs\quic-go_chrome\transfer\server\log.txt:
        //     packets 34-37 were declared lost after later stream data had already been received and ACKed.
        //   runner-logs\quic-go_chrome\transfer\output.txt:
        //     the client read through offset 34015 and then timed out despite quic-go retransmitting the gap.
        // A pending ordered stream read must be woken when retransmitted data fills the gap at the current read offset,
        // even when later out-of-order bytes were already buffered.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 4096,
            localBidirectionalReceiveLimit: 4096);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            runtime.Transition(connectionEvent);
            return true;
        });

        await using QuicStream requestStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, requestStream.Id);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator peerCoordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        byte[] tail = [0x33, 0x44];
        byte[] tailPayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: (ulong)requestStream.Id,
            streamData: tail,
            offset: 2);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            tailPayload,
            minimumPacketNumberExclusive: 5,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out _,
            out byte[] tailPacket));

        QuicConnectionTransitionResult tailResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                tailPacket),
            nowTicks: 10);
        Assert.True(tailResult.StateChanged, DescribeStream(requestStream));
        Assert.Contains("HasContiguousReadableBytes=False", DescribeStream(requestStream), StringComparison.Ordinal);

        byte[] responseBuffer = new byte[4];
        Task<int> pendingRead = requestStream.ReadAsync(responseBuffer, 0, responseBuffer.Length);
        await Task.Delay(150);
        Assert.False(
            pendingRead.IsCompleted,
            $"The read should still be waiting while only the out-of-order tail is buffered. {DescribeStream(requestStream)}");

        byte[] head = [0x11, 0x22];
        byte[] headPayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: (ulong)requestStream.Id,
            streamData: head,
            offset: 0);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            headPayload,
            minimumPacketNumberExclusive: 9,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out _,
            out byte[] headPacket));

        QuicConnectionTransitionResult headResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                runtime.ActivePath.Value.Identity,
                headPacket),
            nowTicks: 11);
        Assert.True(headResult.StateChanged, DescribeStream(requestStream));

        Assert.Equal(4, await pendingRead.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(responseBuffer));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task RuntimeIngressReplay_DeliversBodyThenSurfacesDelayedPeerFinWithoutALengthField()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-221126614-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 1/50 read 1024 bytes from /sour-sad-cat and then idled waiting for more bytes or EOF.
        //   runner-logs\quic-go_chrome\handshakeloss\server\qlog\c9131ce79f3864e7.sqlog:
        //     packet 4 and later retransmissions 8/9/11/12 carried STREAM stream_id=0 offset=1024 length=0 fin=true.
        // quic-go is sending the standalone FIN-only response frame without a length field on that path, so the
        // managed runtime must surface EOF for the exact protected 1-RTT encoding that the live peer retransmits.
        // The request is pinned to the runtime's default 32-byte bidirectional send-credit boundary.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 4096,
            localBidirectionalReceiveLimit: 2048);
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            runtime.Transition(connectionEvent);
            return true;
        });

        await using QuicStream requestStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, requestStream.Id);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator peerCoordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        byte[] response = Enumerable.Range(0, 1024).Select(static index => (byte)(index % 251)).ToArray();

        byte[] responsePayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: (ulong)requestStream.Id,
            streamData: response,
            offset: 0);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            responsePayload,
            minimumPacketNumberExclusive: 2,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out ulong responsePacketNumber,
            out byte[] responsePacket));
        Assert.Equal(3UL, responsePacketNumber);

        QuicConnectionTransitionResult responseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath.Value.Identity,
                responsePacket),
            nowTicks: 10);
        Assert.True(responseResult.StateChanged, DescribeStream(requestStream));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await requestStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));

        Task<int> pendingFollowupRead = requestStream.ReadAsync(new byte[1], 0, 1);
        await Task.Delay(150);
        Assert.False(
            pendingFollowupRead.IsCompleted,
            $"The follow-up read should still be waiting before the delayed no-length FIN arrives. {DescribeStream(requestStream)}");

        byte[] responseFinPayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0D,
            streamId: (ulong)requestStream.Id,
            streamData: [],
            offset: (ulong)response.Length);
        byte[] responseFinPacket = CreateProtectedMinimalApplicationDataPacket(
            runtime.CurrentHandshakeSourceConnectionId.Span,
            packetNumberBytes: [0x00, 0x08],
            responseFinPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 2);

        QuicConnectionTransitionResult responseFinResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 11,
                runtime.ActivePath.Value.Identity,
                responseFinPacket),
            nowTicks: 11);
        Assert.True(responseFinResult.StateChanged, DescribeStream(requestStream));

        Assert.Equal(0, await pendingFollowupRead.WaitAsync(TimeSpan.FromSeconds(5)));
        await requestStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RuntimeIngressReplay_LiveMulticonnectRecoveryContextStillSurfacesDelayedPeerFinWithoutALengthField()
    {
        // Provenance:
        // C:\src\incursa\quic-dotnet\artifacts\interop-runner\20260421-221126614-client-chrome
        //   runner-logs\quic-go_chrome\handshakeloss\output.txt:
        //     connection 1/50 read 1024 bytes from /sour-sad-cat and then idled waiting for more bytes or EOF.
        //   runner-logs\quic-go_chrome\handshakeloss\server\qlog\c9131ce79f3864e7.sqlog:
        //     the managed client first sent an empty open marker, then the HTTP/0.9 request bytes, then a
        //     FIN-only stream frame; later ACK-only peer packets left that open marker unacknowledged while
        //     a delayed FIN-only retransmission at final offset 1024 should still have completed the read.
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionReceiveLimit: 4096,
            localBidirectionalReceiveLimit: 2048,
            localBidirectionalSendLimit: 4096);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        await using QuicStream requestStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        byte[] request = Encoding.ASCII.GetBytes("GET /sour-sad-cat\r\n");
        await requestStream.WriteAsync(request, 0, request.Length).WaitAsync(TimeSpan.FromSeconds(5));

        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionTransitionResult flushResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);
        outboundEffects.AddRange(flushResult.Effects);

        await requestStream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await requestStream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        ulong openMarkerPacketNumber = FindSentStreamFramePacketNumber(
            runtime,
            (ulong)requestStream.Id,
            offset: 0,
            streamDataLength: 0,
            fin: false);
        ulong requestPacketNumber = FindSentStreamFramePacketNumber(
            runtime,
            (ulong)requestStream.Id,
            offset: 0,
            streamDataLength: request.Length,
            fin: false);
        ulong requestFinPacketNumber = FindSentStreamFramePacketNumber(
            runtime,
            (ulong)requestStream.Id,
            offset: (ulong)request.Length,
            streamDataLength: 0,
            fin: true);

        Assert.True(openMarkerPacketNumber < requestPacketNumber);
        Assert.True(requestPacketNumber < requestFinPacketNumber);

        QuicHandshakeFlowCoordinator peerCoordinator = new(runtime.CurrentHandshakeSourceConnectionId);
        byte[] response = Enumerable.Range(0, 1024).Select(static index => (byte)(index % 251)).ToArray();

        byte[] responsePayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0E,
            streamId: (ulong)requestStream.Id,
            streamData: response,
            offset: 0);
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            responsePayload,
            minimumPacketNumberExclusive: 2,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            keyPhase: false,
            out ulong responsePacketNumber,
            out byte[] responsePacket));
        Assert.Equal(3UL, responsePacketNumber);

        QuicConnectionTransitionResult responseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                runtime.ActivePath.Value.Identity,
                responsePacket),
            nowTicks: 20);
        outboundEffects.AddRange(responseResult.Effects);
        Assert.True(responseResult.StateChanged, DescribeStream(requestStream));

        byte[] responseBuffer = new byte[response.Length];
        int responseBytesRead = await requestStream.ReadAsync(responseBuffer, 0, responseBuffer.Length).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(response.Length, responseBytesRead);
        Assert.True(response.AsSpan().SequenceEqual(responseBuffer));

        Task<int> pendingFollowupRead = requestStream.ReadAsync(new byte[1], 0, 1);
        await Task.Delay(150);
        Assert.False(
            pendingFollowupRead.IsCompleted,
            $"The follow-up read should still be waiting before the delayed peer FIN arrives. {DescribeStream(requestStream)}");

        ulong[] acknowledgedClientPackets = GetSentApplicationPacketNumbers(runtime)
            .Where(packetNumber => packetNumber != openMarkerPacketNumber)
            .ToArray();
        Assert.NotEmpty(acknowledgedClientPackets);
        Assert.DoesNotContain(openMarkerPacketNumber, acknowledgedClientPackets);
        outboundEffects.Clear();

        byte[] peerAckPayload = QuicFrameTestData.BuildAckFrame(
            BuildAckFrame(acknowledgedClientPackets));
        Assert.True(peerCoordinator.TryBuildProtectedApplicationDataPacketForRetransmission(
            peerAckPayload,
            minimumPacketNumberExclusive: responsePacketNumber,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            keyPhase: false,
            out ulong peerAckPacketNumber,
            out byte[] peerAckPacket));
        Assert.True(peerAckPacketNumber > responsePacketNumber);

        QuicConnectionTransitionResult peerAckResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 21,
                runtime.ActivePath.Value.Identity,
                peerAckPacket),
            nowTicks: 21);
        outboundEffects.AddRange(peerAckResult.Effects);
        Assert.True(peerAckResult.StateChanged);
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets.Keys,
            key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData && key.PacketNumber == openMarkerPacketNumber);
        ulong retransmittedOpenMarkerPacketNumber = FindSentStreamFramePacketNumber(
            runtime,
            (ulong)requestStream.Id,
            offset: 0,
            streamDataLength: 0,
            fin: false);
        Assert.True(retransmittedOpenMarkerPacketNumber > requestFinPacketNumber);
        Assert.Contains(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => PacketContainsStreamFrame(
                effect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                runtime.CurrentPeerDestinationConnectionId.Span,
                (ulong)requestStream.Id,
                offset: 0,
                streamDataLength: 0,
                fin: false));

        byte[] responseFinPayload = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0D,
            streamId: (ulong)requestStream.Id,
            streamData: [],
            offset: (ulong)response.Length);
        byte[] responseFinPacket = CreateProtectedMinimalApplicationDataPacket(
            runtime.CurrentHandshakeSourceConnectionId.Span,
            packetNumberBytes: [0x00, 0x09],
            responseFinPayload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 2);

        QuicConnectionTransitionResult responseFinResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 22,
                runtime.ActivePath.Value.Identity,
                responseFinPacket),
            nowTicks: 22);
        outboundEffects.AddRange(responseFinResult.Effects);
        Assert.True(responseFinResult.StateChanged, DescribeStream(requestStream));

        Assert.Equal(0, await pendingFollowupRead.WaitAsync(TimeSpan.FromSeconds(5)));
        await requestStream.ReadsClosed.WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamOperationsAfterDispose_AreRejectedHonestly()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        await pair.ClientStream.DisposeAsync();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => pair.ClientStream.WriteAsync(new byte[] { 0x01 }, 0, 1));
        await Assert.ThrowsAsync<ObjectDisposedException>(() => pair.ClientStream.ReadAsync(new byte[1], 0, 1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StreamWritesAfterConnectionClose_AreRejectedWithTheTerminalConnectionOutcome()
    {
        await using LoopbackStreamPair pair = await LoopbackStreamPair.CreateAsync();

        await pair.ClientConnection.CloseAsync(27);

        QuicException exception = await Assert.ThrowsAsync<QuicException>(() => pair.ClientStream.WriteAsync(new byte[] { 0xAA }, 0, 1));
        Assert.Equal(QuicError.ConnectionAborted, exception.QuicError);
        Assert.Equal(27, exception.ApplicationErrorCode);
    }

    private sealed class LoopbackStreamPair : IAsyncDisposable
    {
        private LoopbackStreamPair(
            QuicListener listener,
            QuicConnection serverConnection,
            QuicConnection clientConnection,
            QuicStream serverStream,
            QuicStream clientStream)
        {
            Listener = listener;
            ServerConnection = serverConnection;
            ClientConnection = clientConnection;
            ServerStream = serverStream;
            ClientStream = clientStream;
        }

        public QuicListener Listener { get; }

        public QuicConnection ServerConnection { get; }

        public QuicConnection ClientConnection { get; }

        public QuicStream ServerStream { get; }

        public QuicStream ClientStream { get; }

        public static async Task<LoopbackStreamPair> CreateAsync()
        {
            using X509Certificate2 serverCertificate = QuicLoopbackEstablishmentTestSupport.CreateServerCertificate();
            IPEndPoint listenEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();

            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = listenEndPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 1,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                    QuicLoopbackEstablishmentTestSupport.CreateSupportedServerOptions(serverCertificate)),
            };

            QuicListener listener = await QuicListener.ListenAsync(listenerOptions);
            Task<QuicConnection> acceptConnectionTask = listener.AcceptConnectionAsync().AsTask();
            Task<QuicConnection> connectTask = QuicConnection.ConnectAsync(
                QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port))).AsTask();

            await Task.WhenAll(acceptConnectionTask, connectTask);

            QuicConnection serverConnection = await acceptConnectionTask;
            QuicConnection clientConnection = await connectTask;

            Task<QuicStream> acceptStreamTask = serverConnection.AcceptInboundStreamAsync().AsTask();
            await Task.Yield();
            Task<QuicStream> openStreamTask = clientConnection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional).AsTask();
            await Task.WhenAll(acceptStreamTask, openStreamTask);

            return new LoopbackStreamPair(
                listener,
                serverConnection,
                clientConnection,
                await acceptStreamTask,
                await openStreamTask);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await ServerStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientStream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ServerConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await ClientConnection.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }

            try
            {
                await Listener.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(1));
            }
            catch
            {
            }
        }
    }

    private static async Task<int> ReadWithDiagnosticsAsync(LoopbackStreamPair pair, byte[] buffer, int count)
    {
        try
        {
            return await pair.ServerStream.ReadAsync(buffer, 0, count).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (TimeoutException timeout)
        {
            throw new TimeoutException(
                $"Timed out waiting for peer bytes. Client={QuicLoopbackEstablishmentTestSupport.DescribeConnection(pair.ClientConnection)}; Server={QuicLoopbackEstablishmentTestSupport.DescribeConnection(pair.ServerConnection)}; ClientStream={DescribeStream(pair.ClientStream)}; ServerStream={DescribeStream(pair.ServerStream)}; ClientAppPackets={DescribeApplicationPackets(pair.ClientConnection, pair.ServerConnection)}",
                timeout);
        }
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }

    private static string DescribeApplicationPackets(QuicConnection senderConnection, QuicConnection receiverConnection)
    {
        QuicConnectionRuntime senderRuntime = GetRuntime(senderConnection);
        QuicConnectionRuntime receiverRuntime = GetRuntime(receiverConnection);

        if (!receiverRuntime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue)
        {
            return "<receiver open material unavailable>";
        }

        QuicHandshakeFlowCoordinator receiverHandshakeFlow = GetHandshakeFlow(receiverRuntime);
        QuicConnectionSentPacket[] packets = senderRuntime.SendRuntime.SentPackets.Values
            .Where(static packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .OrderBy(static packet => packet.PacketNumber)
            .ToArray();

        if (packets.Length == 0)
        {
            return "<none>";
        }

        StringBuilder description = new();
        for (int index = 0; index < packets.Length; index++)
        {
            if (index > 0)
            {
                description.Append(" | ");
            }

            QuicConnectionSentPacket packet = packets[index];
            description.Append($"pn={packet.PacketNumber},bytes={packet.PacketBytes.Length},streams={FormatStreamIds(packet.StreamIds)}");

            if (!receiverHandshakeFlow.TryOpenProtectedApplicationDataPacket(
                    packet.PacketBytes.Span,
                    receiverRuntime.TlsState.OneRttOpenPacketProtectionMaterial.Value,
                    out byte[] openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out bool keyPhase))
            {
                description.Append(",open=false");
                continue;
            }

            description.Append($",open=true,keyPhase={keyPhase},frames={DescribeFrames(openedPacket.AsSpan(payloadOffset, payloadLength))}");
        }

        return description.ToString();
    }

    private static string DescribeStream(QuicStream stream)
    {
        QuicConnectionStreamState bookkeeping = stream.Bookkeeping;
        if (!bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot))
        {
            return "<snapshot unavailable>";
        }

        return string.Join(
            "; ",
            [
                $"Id={stream.Id}",
                $"Type={stream.Type}",
                $"CanRead={stream.CanRead}",
                $"CanWrite={stream.CanWrite}",
                $"SendState={snapshot.SendState}",
                $"ReceiveState={snapshot.ReceiveState}",
                $"UniqueBytesSent={snapshot.UniqueBytesSent}",
                $"UniqueBytesReceived={snapshot.UniqueBytesReceived}",
                $"BufferedReadableBytes={snapshot.BufferedReadableBytes}",
                $"HasContiguousReadableBytes={snapshot.HasContiguousReadableBytes}",
                $"HasFinalSize={snapshot.HasFinalSize}",
                $"FinalSize={snapshot.FinalSize}",
                $"ReadOffset={snapshot.ReadOffset}",
            ]);
    }

    private static QuicConnectionRuntime GetRuntime(QuicConnection connection)
    {
        return connection.Runtime;
    }

    private static QuicHandshakeFlowCoordinator GetHandshakeFlow(QuicConnectionRuntime runtime)
    {
        return runtime.HandshakeFlowCoordinator;
    }

    private static byte[] CreateProtectedMinimalApplicationDataPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> packetNumberBytes,
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        int declaredPacketNumberLength)
    {
        int packetNumberLength = packetNumberBytes.Length;
        Assert.InRange(packetNumberLength, 1, 4);
        Assert.InRange(declaredPacketNumberLength, 1, 4);
        Assert.True(
            applicationPayload.Length >= QuicInitialPacketProtection.HeaderProtectionSampleOffset,
            "The plaintext payload must provide enough ciphertext bytes for header protection sampling once the AEAD tag is appended.");

        int packetNumberOffset = 1 + destinationConnectionId.Length;

        byte[] plaintextPacket = new byte[packetNumberOffset + packetNumberLength + applicationPayload.Length];
        plaintextPacket[0] = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | ((declaredPacketNumberLength - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask));
        destinationConnectionId.CopyTo(plaintextPacket.AsSpan(1));
        packetNumberBytes.CopyTo(plaintextPacket.AsSpan(packetNumberOffset));
        applicationPayload.CopyTo(plaintextPacket.AsSpan(packetNumberOffset + packetNumberLength));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        plaintextPacket[..(packetNumberOffset + packetNumberLength)].CopyTo(protectedPacket);

        Span<byte> nonce = stackalloc byte[QuicInitialPacketProtection.AeadNonceLength];
        material.AeadIvBytes.CopyTo(nonce);

        int nonceOffset = nonce.Length - packetNumberLength;
        for (int index = 0; index < packetNumberLength; index++)
        {
            nonce[nonceOffset + index] ^= plaintextPacket[packetNumberOffset + index];
        }

        using (AesGcm aeadGcm = new(material.AeadKey, QuicInitialPacketProtection.AuthenticationTagLength))
        {
            aeadGcm.Encrypt(
                nonce,
                plaintextPacket.AsSpan(packetNumberOffset + packetNumberLength, applicationPayload.Length),
                protectedPacket.AsSpan(packetNumberOffset + packetNumberLength, applicationPayload.Length),
                protectedPacket.AsSpan(plaintextPacket.Length, QuicInitialPacketProtection.AuthenticationTagLength),
                protectedPacket.AsSpan(0, packetNumberOffset + packetNumberLength));
        }

        Span<byte> mask = stackalloc byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
        // QUIC header protection intentionally uses AES-ECB per RFC 9001.

        // codeql[cs/weak-encryption]
        using (Aes aes = Aes.Create())
        {
            aes.Key = material.HeaderProtectionKey.ToArray();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            int bytesWritten = aes.EncryptEcb(
                protectedPacket.AsSpan(
                    packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset,
                    QuicInitialPacketProtection.HeaderProtectionSampleLength),
                mask,
                PaddingMode.None);
            Assert.Equal(QuicInitialPacketProtection.HeaderProtectionSampleLength, bytesWritten);
        }

        protectedPacket[0] ^= (byte)(mask[0] & QuicPacketHeaderBits.ShortTypeSpecificBitsMask);
        for (int index = 0; index < packetNumberLength; index++)
        {
            protectedPacket[packetNumberOffset + index] ^= mask[1 + index];
        }

        return protectedPacket;
    }

    private static ulong[] GetSentApplicationPacketNumbers(QuicConnectionRuntime runtime)
    {
        return runtime.SendRuntime.SentPackets.Keys
            .Where(static key => key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
            .Select(static key => key.PacketNumber)
            .OrderBy(static packetNumber => packetNumber)
            .ToArray();
    }

    private static ulong FindSentStreamFramePacketNumber(
        QuicConnectionRuntime runtime,
        ulong streamId,
        ulong offset,
        int streamDataLength,
        bool fin)
    {
        foreach (QuicConnectionSentPacket packet in runtime.SendRuntime.SentPackets.Values
                     .Where(static packet => packet.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
                     .OrderBy(static packet => packet.PacketNumber))
        {
            if (TryFindStreamFrame(
                    packet.PlaintextPayload.Span,
                    streamId,
                    offset,
                    streamDataLength,
                    fin,
                    out _))
            {
                return packet.PacketNumber;
            }
        }

        Assert.Fail(
            $"No sent application packet contained stream={streamId}, offset={offset}, length={streamDataLength}, fin={fin}.");
        return 0;
    }

    private static QuicAckFrame BuildAckFrame(ReadOnlySpan<ulong> acknowledgedPacketNumbers)
    {
        if (acknowledgedPacketNumbers.IsEmpty)
        {
            throw new ArgumentException("At least one acknowledged packet number is required.", nameof(acknowledgedPacketNumbers));
        }

        ulong[] ordered = acknowledgedPacketNumbers.ToArray();
        Array.Sort(ordered);

        List<(ulong Smallest, ulong Largest)> ranges = [];
        ulong smallest = ordered[0];
        ulong largest = ordered[0];

        for (int index = 1; index < ordered.Length; index++)
        {
            ulong packetNumber = ordered[index];
            if (packetNumber == largest)
            {
                continue;
            }

            if (packetNumber == largest + 1)
            {
                largest = packetNumber;
                continue;
            }

            ranges.Add((smallest, largest));
            smallest = packetNumber;
            largest = packetNumber;
        }

        ranges.Add((smallest, largest));

        (ulong Smallest, ulong Largest) highestRange = ranges[^1];
        List<QuicAckRange> additionalRanges = [];
        ulong previousSmallestAcknowledged = highestRange.Smallest;
        for (int index = ranges.Count - 2; index >= 0; index--)
        {
            (ulong rangeSmallest, ulong rangeLargest) = ranges[index];
            ulong gap = previousSmallestAcknowledged - rangeLargest - 2;
            ulong ackRangeLength = rangeLargest - rangeSmallest;
            additionalRanges.Add(new QuicAckRange(gap, ackRangeLength, rangeSmallest, rangeLargest));
            previousSmallestAcknowledged = rangeSmallest;
        }

        return new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = highestRange.Largest,
            AckDelay = 0,
            FirstAckRange = highestRange.Largest - highestRange.Smallest,
            AdditionalRanges = additionalRanges.ToArray(),
        };
    }

    private static bool PacketContainsStreamFrame(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial openMaterial,
        ReadOnlySpan<byte> destinationConnectionId,
        ulong streamId,
        ulong offset,
        int streamDataLength,
        bool fin)
    {
        QuicHandshakeFlowCoordinator coordinator = new(destinationConnectionId.ToArray());
        if (!coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                openMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out _))
        {
            return false;
        }

        return TryFindStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            streamId,
            offset,
            streamDataLength,
            fin,
            out _);
    }

    private static bool TryFindStreamFrame(
        ReadOnlySpan<byte> payload,
        ulong streamId,
        ulong offset,
        int streamDataLength,
        bool fin,
        out QuicStreamFrame matchingFrame)
    {
        matchingFrame = default;
        int payloadOffset = 0;

        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                return false;
            }

            if (streamFrame.StreamId.Value == streamId
                && streamFrame.Offset == offset
                && streamFrame.StreamDataLength == streamDataLength
                && streamFrame.IsFin == fin)
            {
                matchingFrame = streamFrame;
                return true;
            }

            payloadOffset += streamFrame.ConsumedLength;
        }

        return false;
    }

    private static bool TryFindAnyStreamFrame(
        ReadOnlySpan<byte> payload,
        ulong streamId,
        out QuicStreamFrame matchingFrame)
    {
        matchingFrame = default;
        int payloadOffset = 0;

        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                return false;
            }

            if (streamFrame.StreamId.Value == streamId)
            {
                matchingFrame = streamFrame;
                return true;
            }

            payloadOffset += streamFrame.ConsumedLength;
        }

        return false;
    }

    private static string DescribeFrames(ReadOnlySpan<byte> payload)
    {
        StringBuilder description = new();
        int offset = 0;
        int frameCount = 0;

        while (offset < payload.Length && frameCount < 8)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append($"padding({paddingBytesConsumed})");
                offset += paddingBytesConsumed;
                frameCount++;
                continue;
            }

            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append(
                    $"stream(id={streamFrame.StreamId},off={streamFrame.Offset},len={streamFrame.StreamDataLength},fin={streamFrame.IsFin},data={Convert.ToHexString(streamFrame.StreamData[..Math.Min(streamFrame.StreamDataLength, 8)]).ToLowerInvariant()})");
                offset += streamFrame.ConsumedLength;
                frameCount++;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                description.Append(frameCount == 0 ? string.Empty : ",");
                description.Append("ping");
                offset += pingBytesConsumed;
                frameCount++;
                continue;
            }

            description.Append(frameCount == 0 ? string.Empty : ",");
            description.Append($"unknown(0x{remaining[0]:X2})");
            break;
        }

        return description.Length == 0 ? "<empty>" : description.ToString();
    }

    private static string FormatStreamIds(ulong[]? streamIds)
    {
        if (streamIds is null || streamIds.Length == 0)
        {
            return "<none>";
        }

        return string.Join(",", streamIds);
    }
}
