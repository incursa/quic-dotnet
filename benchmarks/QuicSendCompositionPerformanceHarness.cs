// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.Versioning;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Runs one manifest-bound send-composition cell through real loopback
/// connection, scheduler, buffer-owner, and release seams.
/// </summary>
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class QuicSendCompositionPerformanceHarness
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

    internal static async Task<int> RunAsync(string[] args)
    {
        Options options;
        try
        {
            options = Options.Parse(args);
        }
        catch (Exception exception)
            when (exception is ArgumentException
                or FormatException
                or OverflowException)
        {
            Console.Error.WriteLine(exception.Message);
            return 2;
        }

        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            Console.Error.WriteLine(
                "Incursa.Quic loopback support is unavailable on this host.");
            return 3;
        }

        CampaignEvidenceCollector collector = new();
        Cell cell = Cell.Parse(options.CellId);
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization =
            QuicAdaptiveRuntimePerformanceInteractionAuthorization
                .CreateForReviewedManifest(
                    options.CampaignId,
                    options.ManifestSha256,
                    options.CellId,
                    options.BatchProofSha256,
                    options.BufferProofSha256,
                    cell.BatchMode,
                    cell.BufferValue);

        HarnessResult result = await RunAsync(
            options,
            cell,
            authorization,
            collector).ConfigureAwait(false);
        string json = JsonSerializer.Serialize(result, JsonOptions);
        string outputPath = Path.GetFullPath(options.JsonPath);
        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        await File.WriteAllTextAsync(outputPath, json).ConfigureAwait(false);
        Console.WriteLine(json);
        return result.CorrectnessPassed ? 0 : 1;
    }

    private static async Task<HarnessResult> RunAsync(
        Options options,
        Cell cell,
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization,
        CampaignEvidenceCollector collector)
    {
        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        byte[] requestPayload = CreatePayload(options.PayloadBytes, 0x31);
        byte[] responsePayload = CreatePayload(options.ResponsePayloadBytes, 0x73);

        using X509Certificate2 serverCertificate =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        using X509Certificate2 trustAnchor =
            X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientAuthentication =
            QuicPublicApiLoopbackBenchmarkSupport
                .CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverAuthentication =
            QuicPublicApiLoopbackBenchmarkSupport
                .CreateServerAuthenticationOptions(serverCertificate);

        Console.Error.WriteLine("send-composition-stage:create-pair");
        await using ConnectedPair pair = await ConnectedPair.CreateAsync(
            serverAuthentication,
            clientAuthentication,
            options.ReceiveWindowBytes,
            connectionOptions => Configure(
                connectionOptions,
                cell,
                authorization,
                collector)).ConfigureAwait(false);

        Console.Error.WriteLine("send-composition-stage:warmup");
        await RunSampleAsync(
            pair,
            options,
            requestPayload,
            responsePayload,
            TimeSpan.FromSeconds(options.WarmupSeconds),
            collect: false,
            collector).ConfigureAwait(false);

        Console.Error.WriteLine("send-composition-stage:measurement");
        SampleResult sample = await RunSampleAsync(
            pair,
            options,
            requestPayload,
            responsePayload,
            TimeSpan.FromSeconds(options.DurationSeconds),
            collect: true,
            collector).ConfigureAwait(false);

        Console.Error.WriteLine("send-composition-stage:complete");
        bool releaseCorrect =
            sample.Evidence.CombinedOwnerRents
                == sample.Evidence.CombinedOwnerReleases
            && sample.Evidence.InvalidReleases == 0;
        bool correctnessPassed =
            sample.Failures == 0
            && sample.Operations > 0
            && releaseCorrect;

        return new(
            SchemaVersion:
                "adaptive-runtime-send-composition-performance-raw-v1",
            options.CampaignId,
            options.ManifestSha256,
            options.SourceCommit,
            options.BinarySha256,
            options.CellId,
            BatchValue: Cell.FormatBatchValue(cell.BatchMode),
            BufferValue: Cell.FormatBufferValue(cell.BufferValue),
            options.WorkloadId,
            options.Split,
            options.Block,
            options.Order,
            options.Scenario,
            options.PayloadBytes,
            options.ResponsePayloadBytes,
            options.Concurrency,
            options.ReceiveWindowBytes,
            options.WarmupSeconds,
            options.DurationSeconds,
            startedUtc,
            EndedUtc: DateTimeOffset.UtcNow,
            Runtime: System.Runtime.InteropServices.RuntimeInformation
                .FrameworkDescription,
            OperatingSystem: System.Runtime.InteropServices.RuntimeInformation
                .OSDescription,
            Architecture: System.Runtime.InteropServices.RuntimeInformation
                .ProcessArchitecture.ToString().ToLowerInvariant(),
            ProcessorCount: Environment.ProcessorCount,
            MachineFingerprint: ComputeMachineFingerprint(),
            sample,
            MechanismEventCounts: CreateMechanismEventCounts(sample.Evidence),
            OperationResultCounts: CreateOperationResultCounts(sample.Evidence),
            releaseCorrect,
            correctnessPassed,
            ActiveBehaviorAuthorization: false,
            PerformanceAcceptanceAuthorization: false,
            ProductionActivationAuthorization: false);
    }

    private static void Configure(
        QuicConnectionOptions options,
        Cell cell,
        QuicAdaptiveRuntimePerformanceInteractionAuthorization authorization,
        CampaignEvidenceCollector collector)
    {
        options.ForcedReceiveCreditPolicyMode =
            QuicReceiveCreditPolicyMode.LegacyCurrent;
        options.ForcedApplicationSendBatchPolicyMode = cell.BatchMode;
        options.ApplicationSendBatchObservationMode =
            QuicApplicationSendBatchObservationMode.ObserveOnly;
        options.ApplicationSendBatchEvidenceSink = collector;
        options.ForcedBufferCopyPolicyValue = cell.BufferValue;
        options.BufferCopyObservationMode =
            QuicBufferCopyObservationMode.ObserveOnly;
        options.BufferCopyEvidenceSink = collector;
        options.SendCompositionPerformanceAuthorization = authorization;
    }

    private static async Task<SampleResult> RunSampleAsync(
        ConnectedPair pair,
        Options options,
        byte[] requestPayload,
        byte[] responsePayload,
        TimeSpan duration,
        bool collect,
        CampaignEvidenceCollector collector)
    {
        await collector.WaitForCombinedReleasesAsync(
            TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        EvidenceSnapshot evidenceBefore = collector.Snapshot();
        long allocatedBefore =
            collect ? GC.GetTotalAllocatedBytes(precise: true) : 0;
        TimeSpan cpuBefore =
            collect ? Process.GetCurrentProcess().TotalProcessorTime : default;
        int gen0Before = collect ? GC.CollectionCount(0) : 0;
        int gen1Before = collect ? GC.CollectionCount(1) : 0;
        int gen2Before = collect ? GC.CollectionCount(2) : 0;
        long started = Stopwatch.GetTimestamp();
        long deadline =
            started + (long)(duration.TotalSeconds * Stopwatch.Frequency);

        Task<WorkerResult>[] workers = Enumerable
            .Range(0, options.Concurrency)
            .Select(worker => RunWorkerAsync(
                pair,
                worker,
                options.Scenario,
                requestPayload,
                responsePayload,
                deadline))
            .ToArray();
        WorkerResult[] results = await Task.WhenAll(workers).ConfigureAwait(false);
        TimeSpan elapsed = Stopwatch.GetElapsedTime(started);
        await collector.WaitForCombinedReleasesAsync(
            TimeSpan.FromSeconds(2)).ConfigureAwait(false);
        EvidenceSnapshot evidence =
            collector.Snapshot().Subtract(evidenceBefore);
        long allocated = collect
            ? GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore
            : 0;
        double cpuMilliseconds = collect
            ? (Process.GetCurrentProcess().TotalProcessorTime - cpuBefore)
                .TotalMilliseconds
            : 0;
        int operations = results.Sum(static result => result.Operations);
        int failures = results.Sum(static result => result.Failures);
        double[] latencies = results
            .SelectMany(static result => result.Latencies)
            .Order()
            .ToArray();
        double seconds = elapsed.TotalSeconds;
        long usefulBytesPerOperation = options.Scenario switch
        {
            "upload" => requestPayload.Length,
            "download" => responsePayload.Length,
            "duplex" => requestPayload.Length + responsePayload.Length,
            _ => throw new InvalidOperationException(),
        };
        double[] workerRates = results
            .Select(result => result.Operations / seconds)
            .ToArray();

        return new(
            operations,
            failures,
            elapsed.TotalMilliseconds,
            operations / seconds,
            operations * usefulBytesPerOperation / seconds,
            Percentile(latencies, 0.50),
            Percentile(latencies, 0.95),
            Percentile(latencies, 0.99),
            allocated,
            operations == 0 ? 0 : allocated / (double)operations,
            cpuMilliseconds,
            operations == 0
                ? 0
                : cpuMilliseconds * 1000 / operations,
            collect ? GC.CollectionCount(0) - gen0Before : 0,
            collect ? GC.CollectionCount(1) - gen1Before : 0,
            collect ? GC.CollectionCount(2) - gen2Before : 0,
            JainFairness(workerRates),
            evidence);
    }

    private static async Task<WorkerResult> RunWorkerAsync(
        ConnectedPair pair,
        int worker,
        string scenario,
        byte[] request,
        byte[] response,
        long deadline)
    {
        int operations = 0;
        int failures = 0;
        List<double> latencies = [];
        do
        {
            long started = Stopwatch.GetTimestamp();
            try
            {
                await pair.TransferAsync(
                    scenario,
                    request,
                    response).ConfigureAwait(false);
                operations++;
                latencies.Add(
                    Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            }
            catch
            {
                failures++;
                throw;
            }
        }
        while (Stopwatch.GetTimestamp() < deadline);
        return new(worker, operations, failures, latencies);
    }

    private static byte[] CreatePayload(int length, byte seed)
    {
        byte[] value = GC.AllocateUninitializedArray<byte>(length);
        for (int index = 0; index < value.Length; index++)
        {
            value[index] = unchecked((byte)(seed + index));
        }

        return value;
    }

    private static string ComputeMachineFingerprint()
    {
        string input = string.Join(
            "|",
            Environment.MachineName,
            Environment.ProcessorCount,
            System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture);
        return Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(input)))
            .ToLowerInvariant();
    }

    private static double Percentile(double[] sorted, double percentile)
    {
        if (sorted.Length == 0)
        {
            return 0;
        }

        int index = (int)Math.Ceiling(percentile * sorted.Length) - 1;
        return sorted[Math.Clamp(index, 0, sorted.Length - 1)];
    }

    private static double JainFairness(double[] values)
    {
        if (values.Length == 0)
        {
            return 0;
        }

        double sum = values.Sum();
        double squares = values.Sum(static value => value * value);
        return squares == 0
            ? 0
            : Math.Min(1.0, sum * sum / (values.Length * squares));
    }

    private static MechanismEventCount[] CreateMechanismEventCounts(
        EvidenceSnapshot evidence) =>
    [
        new(
            "application_send_batch_formation",
            "mechanism_event.batch_legal_prefix",
            evidence.BatchLegacyOperations,
            evidence.BatchLegacyBytes),
        new(
            "application_send_batch_formation",
            "mechanism_event.batch_single_eligible",
            evidence.BatchDistinctOperations,
            evidence.BatchDistinctBytes),
        new(
            "buffer_copy_coalescing",
            "mechanism_event.buffer_legacy_prefix",
            evidence.BufferLegacyOperations,
            evidence.BufferLegacyCopiedBytes),
        new(
            "buffer_copy_coalescing",
            "mechanism_event.buffer_two_source_cap",
            evidence.BufferDistinctOperations,
            evidence.BufferDistinctCopiedBytes),
    ];

    private static OperationResultCount[] CreateOperationResultCounts(
        EvidenceSnapshot evidence) =>
    [
        new(
            "application_send_batch_formation",
            "inactive",
            evidence.BatchInactiveOperations),
        new(
            "application_send_batch_formation",
            "fallback",
            evidence.BatchFallbackOperations),
        new(
            "application_send_batch_formation",
            "unclassifiable",
            evidence.BatchUnclassifiableOperations),
        new(
            "buffer_copy_coalescing",
            "inactive",
            evidence.BufferInactiveOperations),
        new(
            "buffer_copy_coalescing",
            "fallback",
            evidence.BufferFallbackOperations),
        new(
            "buffer_copy_coalescing",
            "unclassifiable",
            evidence.BufferUnclassifiableOperations),
        new(
            "buffer_copy_coalescing",
            "terminal_release_failure",
            evidence.InvalidReleases),
    ];

    private sealed class ConnectedPair(
        QuicListener listener,
        QuicConnection client,
        QuicConnection server,
        CancellationTokenSource cancellation) : IAsyncDisposable
    {
        internal static async Task<ConnectedPair> CreateAsync(
            SslServerAuthenticationOptions serverAuthentication,
            SslClientAuthenticationOptions clientAuthentication,
            int receiveWindowBytes,
            Action<QuicConnectionOptions> configure)
        {
            CancellationTokenSource cancellation =
                new(TimeSpan.FromMinutes(5));
            IPEndPoint endpoint =
                QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
            QuicListenerOptions listenerOptions =
                QuicPublicApiLoopbackBenchmarkSupport
                    .CreateIncursaListenerOptions(
                        endpoint,
                        serverAuthentication);
            Func<QuicConnection, SslClientHelloInfo, CancellationToken,
                ValueTask<QuicServerConnectionOptions>> callback =
                    listenerOptions.ConnectionOptionsCallback;
            listenerOptions.ConnectionOptionsCallback =
                async (connection, hello, token) =>
                {
                    QuicServerConnectionOptions options =
                        await callback(connection, hello, token)
                            .ConfigureAwait(false);
                    ApplyReceiveWindow(options, receiveWindowBytes);
                    configure(options);
                    return options;
                };
            QuicListener listener = await QuicListener.ListenAsync(
                listenerOptions,
                cancellation.Token).ConfigureAwait(false);
            try
            {
                Task<QuicConnection> accept =
                    listener.AcceptConnectionAsync(cancellation.Token)
                        .AsTask();
                QuicClientConnectionOptions clientOptions =
                    QuicPublicApiLoopbackBenchmarkSupport
                        .CreateIncursaClientOptions(
                            new IPEndPoint(
                                IPAddress.Loopback,
                                endpoint.Port),
                            clientAuthentication);
                ApplyReceiveWindow(clientOptions, receiveWindowBytes);
                configure(clientOptions);
                Task<QuicConnection> connect = QuicConnection.ConnectAsync(
                    clientOptions,
                    cancellation.Token).AsTask();
                Task first = await Task.WhenAny(
                    accept,
                    connect,
                    Task.Delay(TimeSpan.FromSeconds(30), cancellation.Token))
                    .ConfigureAwait(false);
                if (first == accept && accept.IsFaulted)
                {
                    await accept.ConfigureAwait(false);
                }
                if (first == connect && connect.IsFaulted)
                {
                    await connect.ConfigureAwait(false);
                }
                if (first != accept && first != connect)
                {
                    throw new TimeoutException(
                        "Loopback connection setup exceeded 30 seconds.");
                }
                await Task.WhenAll(accept, connect).ConfigureAwait(false);
                return new(
                    listener,
                    await connect.ConfigureAwait(false),
                    await accept.ConfigureAwait(false),
                    cancellation);
            }
            catch
            {
                await listener.DisposeAsync().ConfigureAwait(false);
                cancellation.Dispose();
                throw;
            }
        }

        internal async Task TransferAsync(
            string scenario,
            byte[] request,
            byte[] response)
        {
            CancellationToken token = cancellation.Token;
            Task<QuicStream> accept =
                server.AcceptInboundStreamAsync(token).AsTask();
            await Task.Yield();
            await using QuicStream clientStream =
                await client.OpenOutboundStreamAsync(
                    QuicStreamType.Bidirectional,
                    token).ConfigureAwait(false);
            Task clientWrite = WriteAsync(
                clientStream,
                scenario == "download" ? new byte[] { 0x41 } : request,
                token);
            await using QuicStream serverStream =
                await accept.ConfigureAwait(false);

            if (scenario == "upload")
            {
                await Task.WhenAll(
                    clientWrite,
                    ReadAsync(serverStream, request, token))
                    .ConfigureAwait(false);
                await Task.WhenAll(
                    WriteAsync(serverStream, new byte[] { 0x42 }, token),
                    ReadAsync(clientStream, new byte[] { 0x42 }, token))
                    .ConfigureAwait(false);
            }
            else if (scenario == "download")
            {
                await Task.WhenAll(
                    clientWrite,
                    ReadAsync(serverStream, new byte[] { 0x41 }, token))
                    .ConfigureAwait(false);
                await Task.WhenAll(
                    WriteAsync(serverStream, response, token),
                    ReadAsync(clientStream, response, token))
                    .ConfigureAwait(false);
            }
            else
            {
                await Task.WhenAll(
                    clientWrite,
                    ReadAsync(serverStream, request, token),
                    WriteAsync(serverStream, response, token),
                    ReadAsync(clientStream, response, token))
                    .ConfigureAwait(false);
            }
        }

        public async ValueTask DisposeAsync()
        {
            cancellation.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                await server.CloseAsync(0, cancellation.Token)
                    .ConfigureAwait(false);
                await client.CloseAsync(0, cancellation.Token)
                    .ConfigureAwait(false);
            }
            finally
            {
                await server.DisposeAsync().ConfigureAwait(false);
                await client.DisposeAsync().ConfigureAwait(false);
                await listener.DisposeAsync().ConfigureAwait(false);
                cancellation.Dispose();
            }
        }

        private static void ApplyReceiveWindow(
            QuicConnectionOptions options,
            int bytes)
        {
            if (bytes <= 0)
            {
                return;
            }

            options.InitialReceiveWindowSizes = new()
            {
                Connection = bytes,
                LocallyInitiatedBidirectionalStream = bytes,
                RemotelyInitiatedBidirectionalStream = bytes,
                UnidirectionalStream = bytes,
            };
        }

        private static async Task WriteAsync(
            QuicStream stream,
            ReadOnlyMemory<byte> payload,
            CancellationToken token)
        {
            await stream.WriteAsync(payload, token).ConfigureAwait(false);
            await stream.CompleteWritesAsync(token).ConfigureAwait(false);
            await stream.WritesClosed.WaitAsync(token).ConfigureAwait(false);
        }

        private static async Task ReadAsync(
            QuicStream stream,
            ReadOnlyMemory<byte> expected,
            CancellationToken token)
        {
            byte[] buffer = new byte[Math.Max(expected.Length, 1)];
            int offset = 0;
            while (offset < expected.Length)
            {
                int read = await stream.ReadAsync(
                    buffer.AsMemory(offset, expected.Length - offset),
                    token).ConfigureAwait(false);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }

                offset += read;
            }

            if (!buffer.AsSpan(0, offset).SequenceEqual(expected.Span))
            {
                throw new InvalidOperationException(
                    "Loopback payload validation failed.");
            }
        }
    }

    private sealed class CampaignEvidenceCollector :
        IQuicApplicationSendBatchEvidenceSink,
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink
    {
        private long batchOperations;
        private long batchLegacy;
        private long batchLegacyBytes;
        private long batchDistinct;
        private long batchDistinctBytes;
        private long batchNoBehavior;
        private long batchUnclassifiable;
        private long batchInactive;
        private long batchFallback;
        private long batchLegalWrites;
        private long batchAppliedWrites;
        private long batchLegalBytes;
        private long batchAppliedBytes;
        private long bufferOperations;
        private long bufferLegacy;
        private long bufferLegacyCopiedBytes;
        private long bufferDistinct;
        private long bufferDistinctCopiedBytes;
        private long bufferNoBehavior;
        private long bufferUnclassifiable;
        private long bufferInactive;
        private long bufferFallback;
        private long bufferLegalSegments;
        private long bufferAppliedSegments;
        private long copiedBytes;
        private long retainedBytes;
        private long combinedOwnerRents;
        private long combinedOwnerReleases;
        private long invalidReleases;

        public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
        {
            Interlocked.Increment(ref batchOperations);
            Interlocked.Add(
                ref batchLegalWrites,
                evidence.OperationEvidence.LegalWriteCount);
            Interlocked.Add(
                ref batchAppliedWrites,
                evidence.OperationEvidence.AppliedWriteCount);
            Interlocked.Add(
                ref batchLegalBytes,
                checked((long)evidence.OperationEvidence.LegalWriteBytes));
            Interlocked.Add(
                ref batchAppliedBytes,
                checked((long)evidence.OperationEvidence.AppliedWriteBytes));
            if (evidence.OperationEvidence.MechanismEvent
                == QuicApplicationSendBatchMechanismEvent
                    .LegalEligiblePrefixUsed)
            {
                Interlocked.Increment(ref batchLegacy);
                Interlocked.Add(
                    ref batchLegacyBytes,
                    checked((long)evidence.OperationEvidence.AppliedWriteBytes));
            }
            if (evidence.OperationEvidence.MechanismEvent
                == QuicApplicationSendBatchMechanismEvent
                    .SingleEligiblePrefixUsed)
            {
                Interlocked.Increment(ref batchDistinct);
                Interlocked.Add(
                    ref batchDistinctBytes,
                    checked((long)evidence.OperationEvidence.AppliedWriteBytes));
            }
            if (evidence.OperationEvidence.MechanismEvent
                is QuicApplicationSendBatchMechanismEvent.NoPacketPlan
                    or QuicApplicationSendBatchMechanismEvent.Unclassifiable)
            {
                Interlocked.Increment(ref batchNoBehavior);
            }
            if (evidence.OperationEvidence.MechanismEvent
                == QuicApplicationSendBatchMechanismEvent.Unclassifiable)
            {
                Interlocked.Increment(ref batchUnclassifiable);
            }
            if (evidence.OperationEvidence.EligibilityReason
                == QuicAdaptiveRuntimeOperationEligibilityReason
                    .StructurallyInactive)
            {
                Interlocked.Increment(ref batchInactive);
            }
            if (evidence.OperationEvidence.EligibilityResult
                == QuicAdaptiveRuntimeOperationEligibilityResult.Clamped)
            {
                Interlocked.Increment(ref batchFallback);
            }

            return true;
        }

        public bool TryPublish(in QuicBufferCopyObservation observation)
        {
            if (observation.Path != QuicBufferCopyPath.CombinedApplicationSend)
            {
                return true;
            }

            Interlocked.Increment(ref bufferOperations);
            Interlocked.Add(
                ref bufferLegalSegments,
                observation.CoalescingEvidence.LegalSourceSegmentCount);
            Interlocked.Add(
                ref bufferAppliedSegments,
                observation.CoalescingEvidence.AppliedSourceSegmentCount);
            Interlocked.Add(ref copiedBytes, (long)observation.CopiedBytes);
            Interlocked.Add(
                ref retainedBytes,
                (long)observation.RetainedCapacityBytes);
            if (observation.CoalescingEvidence.OwnerRented)
            {
                Interlocked.Increment(ref combinedOwnerRents);
            }
            if (observation.CoalescingEvidence.MechanismEvent
                == QuicBufferCopyCoalescingMechanismEvent
                    .ExactCombinedPrefixRetained)
            {
                Interlocked.Increment(ref bufferLegacy);
                Interlocked.Add(
                    ref bufferLegacyCopiedBytes,
                    checked((long)observation.CopiedBytes));
            }
            if (observation.CoalescingEvidence.MechanismEvent
                == QuicBufferCopyCoalescingMechanismEvent
                    .LowerTwoSourceSegmentCapApplied)
            {
                Interlocked.Increment(ref bufferDistinct);
                Interlocked.Add(
                    ref bufferDistinctCopiedBytes,
                    checked((long)observation.CopiedBytes));
            }
            if (observation.CoalescingEvidence.MechanismEvent
                is QuicBufferCopyCoalescingMechanismEvent.NoCombinedOwnerRented
                    or QuicBufferCopyCoalescingMechanismEvent.Unclassifiable)
            {
                Interlocked.Increment(ref bufferNoBehavior);
            }
            if (observation.CoalescingEvidence.MechanismEvent
                == QuicBufferCopyCoalescingMechanismEvent.Unclassifiable)
            {
                Interlocked.Increment(ref bufferUnclassifiable);
            }
            if (observation.CoalescingEvidence.EligibilityReason
                == QuicAdaptiveRuntimeOperationEligibilityReason
                    .StructurallyInactive)
            {
                Interlocked.Increment(ref bufferInactive);
            }
            if (observation.CoalescingEvidence.EligibilityResult
                == QuicAdaptiveRuntimeOperationEligibilityResult.Clamped)
            {
                Interlocked.Increment(ref bufferFallback);
            }

            return true;
        }

        public bool TryPublish(in QuicBufferReleaseObservation observation)
        {
            if (observation.Path == QuicBufferCopyPath.CombinedApplicationSend)
            {
                Interlocked.Increment(ref combinedOwnerReleases);
                if (observation.Validity != QuicBufferReleaseValidity.None)
                {
                    Interlocked.Increment(ref invalidReleases);
                }
            }

            return true;
        }

        internal EvidenceSnapshot Snapshot() => new(
            Interlocked.Read(ref batchOperations),
            Interlocked.Read(ref batchLegacy),
            Interlocked.Read(ref batchLegacyBytes),
            Interlocked.Read(ref batchDistinct),
            Interlocked.Read(ref batchDistinctBytes),
            Interlocked.Read(ref batchNoBehavior),
            Interlocked.Read(ref batchUnclassifiable),
            Interlocked.Read(ref batchInactive),
            Interlocked.Read(ref batchFallback),
            Interlocked.Read(ref batchLegalWrites),
            Interlocked.Read(ref batchAppliedWrites),
            Interlocked.Read(ref batchLegalBytes),
            Interlocked.Read(ref batchAppliedBytes),
            Interlocked.Read(ref bufferOperations),
            Interlocked.Read(ref bufferLegacy),
            Interlocked.Read(ref bufferLegacyCopiedBytes),
            Interlocked.Read(ref bufferDistinct),
            Interlocked.Read(ref bufferDistinctCopiedBytes),
            Interlocked.Read(ref bufferNoBehavior),
            Interlocked.Read(ref bufferUnclassifiable),
            Interlocked.Read(ref bufferInactive),
            Interlocked.Read(ref bufferFallback),
            Interlocked.Read(ref bufferLegalSegments),
            Interlocked.Read(ref bufferAppliedSegments),
            Interlocked.Read(ref copiedBytes),
            Interlocked.Read(ref retainedBytes),
            Interlocked.Read(ref combinedOwnerRents),
            Interlocked.Read(ref combinedOwnerReleases),
            Interlocked.Read(ref invalidReleases));

        internal async Task WaitForCombinedReleasesAsync(TimeSpan timeout)
        {
            long deadline = Stopwatch.GetTimestamp()
                + (long)(timeout.TotalSeconds * Stopwatch.Frequency);
            do
            {
                if (Interlocked.Read(ref combinedOwnerRents)
                    == Interlocked.Read(ref combinedOwnerReleases))
                {
                    return;
                }

                await Task.Delay(10).ConfigureAwait(false);
            }
            while (Stopwatch.GetTimestamp() < deadline);
        }
    }

    private readonly record struct Cell(
        QuicApplicationSendBatchPolicyMode BatchMode,
        QuicBufferCopyPolicyValue BufferValue)
    {
        internal static Cell Parse(string id) => id.ToUpperInvariant() switch
        {
            "A" => new(
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.LegacyCurrent),
            "B" => new(
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.LegacyCurrent),
            "C" => new(
                QuicApplicationSendBatchPolicyMode.LegacyCurrent,
                QuicBufferCopyPolicyValue.MemoryConservative),
            "D" => new(
                QuicApplicationSendBatchPolicyMode.SingleEligible,
                QuicBufferCopyPolicyValue.MemoryConservative),
            _ => throw new ArgumentException("Cell must be A, B, C, or D."),
        };

        internal static string FormatBatchValue(
            QuicApplicationSendBatchPolicyMode value) =>
            value == QuicApplicationSendBatchPolicyMode.SingleEligible
                ? "single_eligible"
                : "legacy_current";

        internal static string FormatBufferValue(QuicBufferCopyPolicyValue value) =>
            value == QuicBufferCopyPolicyValue.MemoryConservative
                ? "memory_conservative"
                : "legacy_current";
    }

    private readonly record struct EvidenceSnapshot(
        long BatchOperations,
        long BatchLegacyOperations,
        long BatchLegacyBytes,
        long BatchDistinctOperations,
        long BatchDistinctBytes,
        long BatchNoBehaviorOperations,
        long BatchUnclassifiableOperations,
        long BatchInactiveOperations,
        long BatchFallbackOperations,
        long BatchLegalWrites,
        long BatchAppliedWrites,
        long BatchLegalBytes,
        long BatchAppliedBytes,
        long BufferOperations,
        long BufferLegacyOperations,
        long BufferLegacyCopiedBytes,
        long BufferDistinctOperations,
        long BufferDistinctCopiedBytes,
        long BufferNoBehaviorOperations,
        long BufferUnclassifiableOperations,
        long BufferInactiveOperations,
        long BufferFallbackOperations,
        long BufferLegalSegments,
        long BufferAppliedSegments,
        long CopiedBytes,
        long RetainedBytes,
        long CombinedOwnerRents,
        long CombinedOwnerReleases,
        long InvalidReleases)
    {
        internal EvidenceSnapshot Subtract(EvidenceSnapshot value) => new(
            BatchOperations - value.BatchOperations,
            BatchLegacyOperations - value.BatchLegacyOperations,
            BatchLegacyBytes - value.BatchLegacyBytes,
            BatchDistinctOperations - value.BatchDistinctOperations,
            BatchDistinctBytes - value.BatchDistinctBytes,
            BatchNoBehaviorOperations - value.BatchNoBehaviorOperations,
            BatchUnclassifiableOperations -
                value.BatchUnclassifiableOperations,
            BatchInactiveOperations - value.BatchInactiveOperations,
            BatchFallbackOperations - value.BatchFallbackOperations,
            BatchLegalWrites - value.BatchLegalWrites,
            BatchAppliedWrites - value.BatchAppliedWrites,
            BatchLegalBytes - value.BatchLegalBytes,
            BatchAppliedBytes - value.BatchAppliedBytes,
            BufferOperations - value.BufferOperations,
            BufferLegacyOperations - value.BufferLegacyOperations,
            BufferLegacyCopiedBytes - value.BufferLegacyCopiedBytes,
            BufferDistinctOperations - value.BufferDistinctOperations,
            BufferDistinctCopiedBytes - value.BufferDistinctCopiedBytes,
            BufferNoBehaviorOperations - value.BufferNoBehaviorOperations,
            BufferUnclassifiableOperations -
                value.BufferUnclassifiableOperations,
            BufferInactiveOperations - value.BufferInactiveOperations,
            BufferFallbackOperations - value.BufferFallbackOperations,
            BufferLegalSegments - value.BufferLegalSegments,
            BufferAppliedSegments - value.BufferAppliedSegments,
            CopiedBytes - value.CopiedBytes,
            RetainedBytes - value.RetainedBytes,
            CombinedOwnerRents - value.CombinedOwnerRents,
            CombinedOwnerReleases - value.CombinedOwnerReleases,
            InvalidReleases - value.InvalidReleases);
    }

    private sealed record WorkerResult(
        int Worker,
        int Operations,
        int Failures,
        List<double> Latencies);

    private sealed record SampleResult(
        int Operations,
        int Failures,
        double ElapsedMilliseconds,
        double OperationsPerSecond,
        double UsefulBytesPerSecond,
        double LatencyP50Milliseconds,
        double LatencyP95Milliseconds,
        double LatencyP99Milliseconds,
        long AllocatedBytes,
        double AllocatedBytesPerOperation,
        double CpuMilliseconds,
        double CpuMicrosecondsPerOperation,
        int Gen0Collections,
        int Gen1Collections,
        int Gen2Collections,
        double JainFairness,
        EvidenceSnapshot Evidence);

    private sealed record MechanismEventCount(
        string AxisId,
        string MechanismEventId,
        long OperationCount,
        long WorkAmount);

    private sealed record OperationResultCount(
        string AxisId,
        string ResultKind,
        long OperationCount);

    private sealed record HarnessResult(
        string SchemaVersion,
        string CampaignId,
        string ManifestSha256,
        string SourceCommit,
        string BinarySha256,
        string CellId,
        string BatchValue,
        string BufferValue,
        string WorkloadId,
        string Split,
        int Block,
        int Order,
        string Scenario,
        int PayloadBytes,
        int ResponsePayloadBytes,
        int Concurrency,
        int ReceiveWindowBytes,
        int WarmupSeconds,
        int DurationSeconds,
        DateTimeOffset StartedUtc,
        DateTimeOffset EndedUtc,
        string Runtime,
        string OperatingSystem,
        string Architecture,
        int ProcessorCount,
        string MachineFingerprint,
        SampleResult Sample,
        MechanismEventCount[] MechanismEventCounts,
        OperationResultCount[] OperationResultCounts,
        bool ReleaseCorrect,
        bool CorrectnessPassed,
        bool ActiveBehaviorAuthorization,
        bool PerformanceAcceptanceAuthorization,
        bool ProductionActivationAuthorization);

    private sealed record Options(
        string CampaignId,
        string ManifestSha256,
        string BatchProofSha256,
        string BufferProofSha256,
        string SourceCommit,
        string BinarySha256,
        string CellId,
        string WorkloadId,
        string Split,
        int Block,
        int Order,
        string Scenario,
        int PayloadBytes,
        int ResponsePayloadBytes,
        int Concurrency,
        int ReceiveWindowBytes,
        int WarmupSeconds,
        int DurationSeconds,
        string JsonPath)
    {
        internal static Options Parse(string[] args)
        {
            Dictionary<string, string> values =
                new(StringComparer.OrdinalIgnoreCase);
            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length
                    || !args[index].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        "Every send-composition option requires a value.");
                }

                values.Add(args[index], args[index + 1]);
            }

            string Required(string name) =>
                values.TryGetValue(name, out string? value)
                    && !string.IsNullOrWhiteSpace(value)
                    ? value
                    : throw new ArgumentException(
                        $"Required option '{name}' is missing.");
            int Integer(string name, int minimum = 0)
            {
                int value = int.Parse(
                    Required(name),
                    System.Globalization.CultureInfo.InvariantCulture);
                return value >= minimum
                    ? value
                    : throw new ArgumentException(
                        $"Option '{name}' must be at least {minimum}.");
            }

            string scenario = Required("--scenario").ToLowerInvariant();
            if (scenario is not ("upload" or "download" or "duplex"))
            {
                throw new ArgumentException(
                    "Scenario must be upload, download, or duplex.");
            }

            return new(
                Required("--campaign-id"),
                RequiredHash("--manifest-sha256"),
                RequiredHash("--batch-proof-sha256"),
                RequiredHash("--buffer-proof-sha256"),
                RequiredGitCommit("--source-commit"),
                RequiredHash("--binary-sha256"),
                Required("--cell"),
                Required("--workload-id"),
                Required("--split"),
                Integer("--block", 0),
                Integer("--order", 0),
                scenario,
                Integer("--payload-bytes", 1),
                Integer("--response-payload-bytes", 1),
                Integer("--concurrency", 1),
                Integer("--receive-window-bytes", 0),
                Integer("--warmup-seconds", 1),
                Integer("--duration-seconds", 1),
                Required("--json"));

            string RequiredHash(string name)
            {
                string value = Required(name).ToLowerInvariant();
                return value.Length == 64
                    && value.All(static character =>
                        character is >= '0' and <= '9'
                            or >= 'a' and <= 'f')
                    ? value
                    : throw new ArgumentException(
                        $"Option '{name}' must be a lowercase SHA-256 value.");
            }

            string RequiredGitCommit(string name)
            {
                string value = Required(name).ToLowerInvariant();
                return value.Length is 40 or 64
                    && value.All(static character =>
                        character is >= '0' and <= '9'
                            or >= 'a' and <= 'f')
                    ? value
                    : throw new ArgumentException(
                        $"Option '{name}' must be a lowercase Git object ID.");
            }
        }
    }
}
