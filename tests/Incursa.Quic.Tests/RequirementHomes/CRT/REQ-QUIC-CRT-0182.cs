// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0182")]
public sealed class REQ_QUIC_CRT_0182
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObserveOnlyCopyOperationsRemainLegacyAndAccumulate()
    {
        QuicBufferCopyEpochAccumulator accumulator = new();
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = accumulator,
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.FormattedStreamPayload,
            QuicBufferCopyOperation.Format,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 100,
            copiedBytes: 100,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 120,
            retainedCapacityBytes: 128);
        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.CombinedApplicationSend,
            QuicBufferCopyOperation.Combine,
            QuicBufferCopyDecisionBoundary.PacketPlan,
            joinOperationSequence: null,
            logicalBytes: 200,
            copiedBytes: 200,
            sourceSegmentCount: 2,
            requestedCapacityBytes: 200,
            retainedCapacityBytes: 256);

        QuicBufferCopyEpochSummary summary =
            accumulator.CaptureAndReset();
        Assert.True(summary.HasObservation);
        Assert.Equal(1UL, summary.FirstOperationSequence);
        Assert.Equal(2UL, summary.LastOperationSequence);
        Assert.Equal(2UL, summary.OperationCount);
        Assert.Equal(1UL, summary.FormattedStreamPayloadCount);
        Assert.Equal(1UL, summary.CombinedApplicationSendCount);
        Assert.Equal(1UL, summary.FormatCount);
        Assert.Equal(1UL, summary.CombineCount);
        Assert.Equal(300UL, summary.TotalLogicalBytes);
        Assert.Equal(300UL, summary.TotalCopiedBytes);
        Assert.Equal(384UL, summary.TotalRetainedCapacityBytes);
        Assert.True(
            (summary.Validity
                & QuicBufferCopyValidity.MissingTerminalReleaseCorrelation)
            != 0);

        Assert.False(accumulator.CaptureAndReset().HasObservation);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ObservationConfigurationRequiresAnExactModeAndSinkPair()
    {
        using QuicConnectionRuntime missingSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => missingSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                }));

        using QuicConnectionRuntime disabledWithSink = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<InvalidOperationException>(
            () => disabledWithSink.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyEvidenceSink =
                        new QuicBufferCopyEpochAccumulator(),
                }));

        using QuicConnectionRuntime invalidMode = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.Throws<ArgumentOutOfRangeException>(
            () => invalidMode.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        (QuicBufferCopyObservationMode)byte.MaxValue,
                }));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesBufferObservationModeAndSink()
    {
        QuicBufferCopyEpochAccumulator sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(
            selectedOptions,
            returnedOptions);

        Assert.Equal(
            QuicBufferCopyObservationMode.ObserveOnly,
            selectedOptions.BufferCopyObservationMode);
        Assert.Same(sink, selectedOptions.BufferCopyEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ThrowingEvidenceSinkCannotInterruptCopyOwnershipPath()
    {
        using QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicServerConnectionOptions
        {
            BufferCopyObservationMode =
                QuicBufferCopyObservationMode.ObserveOnly,
            BufferCopyEvidenceSink = new ThrowingSink(),
        });

        runtime.TryPublishBufferCopyObservation(
            QuicBufferCopyPath.OversizedRawQueue,
            QuicBufferCopyOperation.Copy,
            QuicBufferCopyDecisionBoundary.LogicalWriteAdmission,
            joinOperationSequence: 1,
            logicalBytes: 64,
            copiedBytes: 64,
            sourceSegmentCount: 1,
            requestedCapacityBytes: 64,
            retainedCapacityBytes: 64);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedQueueRetentionTracksOwnershipTransitions()
    {
        QuicApplicationSendQueue queue = new();
        byte[] first = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.QueuedRawStreamData);
        byte[] second = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.QueuedRawStreamData);
        byte[] replacement = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.QueuedRawStreamData);
        queue.Enqueue(
            streamId: 1,
            priority: 0,
            first,
            streamPayloadLength: 20,
            firstEnqueuedAtMicros: 1_000);
        queue.Enqueue(
            streamId: 2,
            priority: 0,
            second,
            streamPayloadLength: 40,
            firstEnqueuedAtMicros: 2_000);

        QuicRetentionSnapshot initial =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(2, initial.RetainedBufferCount);
        Assert.Equal(
            first.Length + second.Length,
            initial.RetainedByteCount);
        Assert.Equal(4, initial.OldestAgeMilliseconds);

        Assert.True(queue.TryGetLatestQueuedWriteForStream(
            streamId: 1,
            out PendingApplicationSendRequest firstRequest));
        Assert.True(queue.TryReplaceQueuedWritePayload(
            firstRequest.Sequence,
            replacement,
            streamPayloadLength: 80));
        QuicRetentionSnapshot replaced =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(
            replacement.Length + second.Length,
            replaced.RetainedByteCount);

        Assert.True(queue.TryRemoveQueuedWrite(
            firstRequest.Sequence,
            returnPayloads: true));
        QuicRetentionSnapshot remaining =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(second.Length, remaining.RetainedByteCount);
        Assert.Equal(3, remaining.OldestAgeMilliseconds);

        queue.Clear();
        QuicRetentionSnapshot empty =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedRetransmissionRetentionTracksOwnershipTransitions()
    {
        QuicRetransmissionQueue queue = new();
        byte[] first = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.Retransmission);
        byte[] second = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.Retransmission);
        byte[] shared = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.Retransmission);
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 20,
            SentAtMicros: 1_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: default,
            PlaintextPayload: first.AsMemory(0, 20),
            PlaintextPayloadOwner: first));
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 40,
            SentAtMicros: 2_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: second.AsMemory(0, 40),
            PacketBytesOwner: second));
        queue.QueueRetransmission(new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 3,
            PayloadBytes: 80,
            SentAtMicros: 3_000,
            ProbePacket: false,
            CryptoMetadata: null,
            PacketBytes: shared.AsMemory(0, 80),
            PlaintextPayload: shared.AsMemory(0, 80),
            PlaintextPayloadOwner: shared,
            PacketBytesOwner: shared));

        QuicRetentionSnapshot initial =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(3, initial.RetainedBufferCount);
        Assert.Equal(
            first.Length + second.Length + shared.Length,
            initial.RetainedByteCount);
        Assert.Equal(4, initial.OldestAgeMilliseconds);

        Assert.True(
            queue.TryDiscardPendingRetransmissionsOlderThan(2_000));
        QuicRetentionSnapshot retained =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(2, retained.RetainedBufferCount);
        Assert.Equal(
            second.Length + shared.Length,
            retained.RetainedByteCount);
        Assert.Equal(3, retained.OldestAgeMilliseconds);

        Assert.True(queue.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan dequeuedSecond));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            dequeuedSecond);
        QuicRetentionSnapshot remaining =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(shared.Length, remaining.RetainedByteCount);
        Assert.Equal(2, remaining.OldestAgeMilliseconds);

        Assert.True(queue.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan dequeuedShared));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            dequeuedShared);
        QuicRetentionSnapshot empty =
            queue.CaptureRetentionSnapshot(nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MaintainedSentPacketRetentionTracksOwnershipTransitions()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] replaced = QuicBufferPool.RentBytes(
            20,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] replacement = QuicBufferPool.RentBytes(
            40,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] secondPlaintext = QuicBufferPool.RentBytes(
            80,
            QuicBufferPoolOwner.SentPacketRetention);
        byte[] secondPacket = QuicBufferPool.RentBytes(
            160,
            QuicBufferPoolOwner.SentPacketRetention);
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 20,
            SentAtMicros: 1_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: replaced.AsMemory(0, 20),
            PlaintextPayloadOwner: replaced));
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 40,
            SentAtMicros: 1_500,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PlaintextPayload: replacement.AsMemory(0, 40),
            PlaintextPayloadOwner: replacement));
        ReadOnlyMemory<byte> protectedPacket =
            secondPacket.AsMemory(0, 160);
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 2,
            PayloadBytes: 160,
            SentAtMicros: 2_000,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            PacketBytes: protectedPacket,
            PlaintextPayload: secondPlaintext.AsMemory(0, 80),
            PlaintextPayloadOwner: secondPlaintext,
            PacketBytesOwner: secondPacket));

        QuicRetentionSnapshot initial =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000,
                out _);
        Assert.Equal(3, initial.RetainedBufferCount);
        Assert.Equal(
            replacement.Length
                + secondPlaintext.Length
                + secondPacket.Length,
            initial.RetainedByteCount);
        Assert.Equal(3.5, initial.OldestAgeMilliseconds);
        Assert.Equal(
            initial,
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000));

        Assert.True(runtime.TryDetachLatestRebuildablePacketBytes(
            protectedPacket,
            out byte[]? detachedPacket));
        Assert.Same(secondPacket, detachedPacket);
        QuicRetentionSnapshot detached =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(2, detached.RetainedBufferCount);
        Assert.Equal(
            replacement.Length + secondPlaintext.Length,
            detached.RetainedByteCount);
        QuicBufferPool.ReturnBytes(detachedPacket);

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            handshakeConfirmed: true));
        QuicRetentionSnapshot remaining =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(1, remaining.RetainedBufferCount);
        Assert.Equal(
            secondPlaintext.Length,
            remaining.RetainedByteCount);
        Assert.Equal(3, remaining.OldestAgeMilliseconds);

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 2,
            handshakeConfirmed: true));
        QuicRetentionSnapshot empty =
            runtime.CaptureSentPacketRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(0, empty.RetainedBufferCount);
        Assert.Equal(0, empty.RetainedByteCount);
        Assert.Null(empty.OldestAgeMilliseconds);

        QuicRetentionSnapshot transferred =
            runtime.CaptureRetransmissionRetentionSnapshot(
                nowMicros: 5_000);
        Assert.Equal(1, transferred.RetainedBufferCount);
        Assert.Equal(
            secondPlaintext.Length,
            transferred.RetainedByteCount);
        Assert.True(runtime.TryDequeueRetransmission(
            out QuicConnectionRetransmissionPlan retransmission));
        QuicConnectionSendRuntime.ReleaseRetransmissionPlanResources(
            retransmission);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ObservationAndEpochSummaryPassSchemaAndSemanticValidation()
    {
        string repoRoot =
            AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"buffer-copy-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            RecordingSink sink = new();
            using QuicConnectionRuntime runtime = new(
                QuicConnectionStreamStateTestHelpers.CreateState());
            runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicServerConnectionOptions
                {
                    BufferCopyObservationMode =
                        QuicBufferCopyObservationMode.ObserveOnly,
                    BufferCopyEvidenceSink = sink,
                });
            runtime.TryPublishBufferCopyObservation(
                QuicBufferCopyPath.SentPacketPlaintextRetention,
                QuicBufferCopyOperation.Retain,
                QuicBufferCopyDecisionBoundary.SentPacketRetention,
                joinOperationSequence: 7,
                logicalBytes: 80,
                copiedBytes: 80,
                sourceSegmentCount: 1,
                requestedCapacityBytes: 80,
                retainedCapacityBytes: 128);
            QuicBufferCopyObservation observation =
                Assert.Single(sink.Observations);
            QuicBufferCopyEpochAccumulator accumulator = new();
            Assert.True(accumulator.TryPublish(in observation));
            QuicBufferCopyEpochSummary summary =
                accumulator.CaptureAndReset();

            JsonSerializerOptions options =
                new(JsonSerializerDefaults.Web);
            options.Converters.Add(new JsonStringEnumConverter());
            string observationPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-observations.jsonl");
            string epochPath = Path.Combine(
                temporaryDirectory,
                "buffer-copy-epoch.json");
            File.WriteAllText(
                observationPath,
                JsonSerializer.Serialize(observation, options));
            File.WriteAllText(
                epochPath,
                JsonSerializer.Serialize(summary, options));

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeBufferCopyEvidence.ps1",
                    "-ObservationPath",
                    observationPath,
                    "-EpochSummaryPath",
                    epochPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument validation =
                JsonDocument.Parse(result.Output);
            Assert.True(
                validation.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("observationRowCount")
                    .GetInt32());
            Assert.Equal(
                1,
                validation.RootElement
                    .GetProperty("operationCount")
                    .GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private sealed class RecordingSink : IQuicBufferCopyEvidenceSink
    {
        internal List<QuicBufferCopyObservation> Observations { get; } = [];

        public bool TryPublish(
            in QuicBufferCopyObservation observation)
        {
            Observations.Add(observation);
            return true;
        }
    }

    private sealed class ThrowingSink : IQuicBufferCopyEvidenceSink
    {
        public bool TryPublish(
            in QuicBufferCopyObservation observation)
            => throw new InvalidOperationException("diagnostic sink failure");
    }
}
