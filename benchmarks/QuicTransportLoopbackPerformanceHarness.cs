// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using IncursaClientConnection = global::Incursa.Quic.QuicConnection;
using IncursaListener = global::Incursa.Quic.QuicListener;
using IncursaStream = global::Incursa.Quic.QuicStream;
using IncursaStreamType = global::Incursa.Quic.QuicStreamType;
using SystemNetClientConnection = global::System.Net.Quic.QuicConnection;
using SystemNetListener = global::System.Net.Quic.QuicListener;
using SystemNetStream = global::System.Net.Quic.QuicStream;
using SystemNetStreamType = global::System.Net.Quic.QuicStreamType;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Runs repeated, exact public QUIC stream transfers on established loopback connections.
/// </summary>
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class QuicTransportLoopbackPerformanceHarness
{
    private static readonly byte[] RequestMarker = [0x41];
    private static readonly byte[] ResponseMarker = [0x42];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
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
        catch (Exception exception) when (exception is ArgumentException or FormatException or OverflowException)
        {
            Console.Error.WriteLine(exception.Message);
            WriteUsage();
            return 2;
        }

        if (options.Implementations.Contains(Implementation.Incursa)
            && (!IncursaClientConnection.IsSupported || !IncursaListener.IsSupported))
        {
            Console.Error.WriteLine("Incursa.Quic loopback support is unavailable on this platform.");
            return 3;
        }

        if (options.Implementations.Contains(Implementation.SystemNet)
            && (!SystemNetClientConnection.IsSupported || !SystemNetListener.IsSupported))
        {
            Console.Error.WriteLine("System.Net.Quic loopback support is unavailable on this platform.");
            return 3;
        }

        HarnessResult result = await RunMatrixAsync(options).ConfigureAwait(false);
        string json = JsonSerializer.Serialize(result, JsonOptions);
        Console.WriteLine(json);

        if (!string.IsNullOrWhiteSpace(options.JsonPath))
        {
            string path = Path.GetFullPath(options.JsonPath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await File.WriteAllTextAsync(path, json).ConfigureAwait(false);
        }

        return result.Results.All(static result => result.Failures == 0) ? 0 : 1;
    }

    private static async Task<HarnessResult> RunMatrixAsync(Options options)
    {
        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        List<ShapeResult> results = [];

        using X509Certificate2 serverCertificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
        using X509Certificate2 trustAnchor = X509CertificateLoader.LoadCertificate(serverCertificate.RawData);
        SslClientAuthenticationOptions clientOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateClientAuthenticationOptions(trustAnchor);
        SslServerAuthenticationOptions serverOptions =
            QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(serverCertificate);

        foreach (int payloadSize in options.PayloadSizes)
        {
            byte[] requestPayload = CreateDeterministicBytes(payloadSize, 0x11);
            byte[] responsePayload = CreateDeterministicBytes(payloadSize, 0x53);

            foreach (Scenario scenario in options.Scenarios)
            {
                foreach (int concurrency in options.ConcurrencyLevels)
                {
                    foreach (Implementation implementation in options.Implementations)
                    {
                        Console.Error.WriteLine(
                            $"Preparing {FormatImplementation(implementation)} {FormatScenario(scenario)} " +
                            $"payload={payloadSize:N0} c{concurrency}.");
                        await using IConnectedPair pair = implementation switch
                        {
                            Implementation.Incursa => await IncursaConnectedPair.CreateAsync(
                                serverOptions,
                                clientOptions).ConfigureAwait(false),
                            Implementation.SystemNet => await SystemNetConnectedPair.CreateAsync(
                                serverOptions,
                                clientOptions).ConfigureAwait(false),
                            _ => throw new ArgumentOutOfRangeException(nameof(implementation)),
                        };
                        await using QuicRuntimeDiagnosticsCollector? diagnostics =
                            options.Diagnostics && implementation == Implementation.Incursa
                                ? QuicRuntimeDiagnosticsCollector.Start()
                                : null;

                        Console.Error.WriteLine($"  c{concurrency}: warmup");
                        await RunSampleAsync(
                            pair,
                            scenario,
                            requestPayload,
                            responsePayload,
                            concurrency,
                            TimeSpan.FromSeconds(options.WarmupSeconds),
                            collectMetrics: false,
                            diagnostics: null).ConfigureAwait(false);

                        List<SampleResult> samples = new(options.Samples);
                        for (int sampleIndex = 0; sampleIndex < options.Samples; sampleIndex++)
                        {
                            Console.Error.WriteLine($"  c{concurrency}: sample {sampleIndex + 1}/{options.Samples}");
                            GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: false);
                            GC.WaitForPendingFinalizers();
                            samples.Add(await RunSampleAsync(
                                pair,
                                scenario,
                                requestPayload,
                                responsePayload,
                                concurrency,
                                TimeSpan.FromSeconds(options.DurationSeconds),
                                collectMetrics: true,
                                diagnostics).ConfigureAwait(false));
                        }

                        results.Add(Summarize(
                            implementation,
                            scenario,
                            payloadSize,
                            concurrency,
                            samples));
                        Console.Error.WriteLine($"  c{concurrency}: complete");
                    }
                }
            }
        }

        return new HarnessResult(
            SchemaVersion: 1,
            Label: options.Label,
            StartedUtc: startedUtc,
            Runtime: System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            OperatingSystem: System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            ProcessorCount: Environment.ProcessorCount,
            DurationSeconds: options.DurationSeconds,
            WarmupSeconds: options.WarmupSeconds,
            Samples: options.Samples,
            DiagnosticsEnabled: options.Diagnostics,
            Results: results);
    }

    private static async Task<SampleResult> RunSampleAsync(
        IConnectedPair pair,
        Scenario scenario,
        byte[] requestPayload,
        byte[] responsePayload,
        int concurrency,
        TimeSpan duration,
        bool collectMetrics,
        QuicRuntimeDiagnosticsCollector? diagnostics)
    {
        WorkerState[] states = new WorkerState[concurrency];
        for (int index = 0; index < states.Length; index++)
        {
            states[index] = new WorkerState(requestPayload.Length, responsePayload.Length);
        }

        diagnostics?.BeginSample();
        long allocatedBefore = collectMetrics ? GC.GetTotalAllocatedBytes(precise: true) : 0;
        int gen0Before = collectMetrics ? GC.CollectionCount(0) : 0;
        int gen1Before = collectMetrics ? GC.CollectionCount(1) : 0;
        int gen2Before = collectMetrics ? GC.CollectionCount(2) : 0;
        long started = Stopwatch.GetTimestamp();
        long deadline = started + (long)(duration.TotalSeconds * Stopwatch.Frequency);

        Task<WorkerResult>[] workers = new Task<WorkerResult>[concurrency];
        for (int index = 0; index < workers.Length; index++)
        {
            workers[index] = RunWorkerAsync(
                pair,
                scenario,
                requestPayload,
                responsePayload,
                deadline,
                states[index]);
        }

        WorkerResult[] workerResults;
        QuicRuntimeDiagnosticsResult? runtimeDiagnostics;
        TimeSpan elapsed;
        try
        {
            workerResults = await Task.WhenAll(workers).ConfigureAwait(false);
            elapsed = Stopwatch.GetElapsedTime(started);
        }
        finally
        {
            runtimeDiagnostics = diagnostics?.CompleteSample();
        }

        long allocatedAfter = collectMetrics ? GC.GetTotalAllocatedBytes(precise: true) : 0;

        int operations = workerResults.Sum(static result => result.Operations);
        int failures = workerResults.Sum(static result => result.Failures);
        double[] latencies = workerResults.SelectMany(static result => result.LatenciesMilliseconds).ToArray();
        Array.Sort(latencies);
        double elapsedSeconds = elapsed.TotalSeconds;
        int transferredBytesPerOperation = scenario == Scenario.Duplex
            ? requestPayload.Length + responsePayload.Length
            : requestPayload.Length;
        double throughputBytesPerSecond = operations * (double)transferredBytesPerOperation / elapsedSeconds;

        return new SampleResult(
            Operations: operations,
            Failures: failures,
            ElapsedMilliseconds: elapsed.TotalMilliseconds,
            OperationsPerSecond: operations / elapsedSeconds,
            ThroughputBytesPerSecond: throughputBytesPerSecond,
            ThroughputMebibytesPerSecond: throughputBytesPerSecond / (1024 * 1024),
            LatencyP50Milliseconds: Percentile(latencies, 0.50),
            LatencyP95Milliseconds: Percentile(latencies, 0.95),
            LatencyP99Milliseconds: Percentile(latencies, 0.99),
            AllocatedBytes: collectMetrics ? allocatedAfter - allocatedBefore : 0,
            AllocatedBytesPerOperation: collectMetrics && operations > 0
                ? (allocatedAfter - allocatedBefore) / (double)operations
                : 0,
            Gen0Collections: collectMetrics ? GC.CollectionCount(0) - gen0Before : 0,
            Gen1Collections: collectMetrics ? GC.CollectionCount(1) - gen1Before : 0,
            Gen2Collections: collectMetrics ? GC.CollectionCount(2) - gen2Before : 0,
            MetricsInstrumentationEnabled: diagnostics is not null,
            RuntimeDiagnostics: runtimeDiagnostics);
    }

    private static async Task<WorkerResult> RunWorkerAsync(
        IConnectedPair pair,
        Scenario scenario,
        byte[] requestPayload,
        byte[] responsePayload,
        long deadline,
        WorkerState state)
    {
        int operations = 0;
        int failures = 0;

        do
        {
            long started = Stopwatch.GetTimestamp();
            try
            {
                await pair.TransferAsync(
                    scenario,
                    requestPayload,
                    responsePayload,
                    state.RequestBuffer,
                    state.ResponseBuffer).ConfigureAwait(false);
                operations++;
                state.LatenciesMilliseconds.Add(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            }
            catch (Exception exception)
            {
                failures++;
                throw new InvalidOperationException(
                    $"{pair.Name} {scenario} transfer failed after {operations} successful operations.",
                    exception);
            }
        }
        while (Stopwatch.GetTimestamp() < deadline);

        return new WorkerResult(operations, failures, state.LatenciesMilliseconds);
    }

    private static ShapeResult Summarize(
        Implementation implementation,
        Scenario scenario,
        int payloadSize,
        int concurrency,
        List<SampleResult> samples)
    {
        double[] throughputs = samples.Select(static sample => sample.ThroughputMebibytesPerSecond).Order().ToArray();
        double mean = throughputs.Average();
        double variance = throughputs.Sum(value => Math.Pow(value - mean, 2)) / throughputs.Length;

        return new ShapeResult(
            Implementation: FormatImplementation(implementation),
            Scenario: FormatScenario(scenario),
            PayloadSizeBytes: payloadSize,
            Concurrency: concurrency,
            MedianThroughputMebibytesPerSecond: Percentile(throughputs, 0.50),
            MinimumThroughputMebibytesPerSecond: throughputs[0],
            MaximumThroughputMebibytesPerSecond: throughputs[^1],
            ThroughputRangePercent: mean == 0 ? 0 : (throughputs[^1] - throughputs[0]) / mean * 100,
            ThroughputCoefficientOfVariationPercent: mean == 0 ? 0 : Math.Sqrt(variance) / mean * 100,
            MedianOperationsPerSecond: Percentile(
                samples.Select(static sample => sample.OperationsPerSecond).Order().ToArray(),
                0.50),
            MedianLatencyP50Milliseconds: Percentile(
                samples.Select(static sample => sample.LatencyP50Milliseconds).Order().ToArray(),
                0.50),
            MedianLatencyP95Milliseconds: Percentile(
                samples.Select(static sample => sample.LatencyP95Milliseconds).Order().ToArray(),
                0.50),
            MedianLatencyP99Milliseconds: Percentile(
                samples.Select(static sample => sample.LatencyP99Milliseconds).Order().ToArray(),
                0.50),
            MedianAllocatedBytesPerOperation: Percentile(
                samples.Select(static sample => sample.AllocatedBytesPerOperation).Order().ToArray(),
                0.50),
            Failures: samples.Sum(static sample => sample.Failures),
            SampleResults: samples);
    }

    private static double Percentile(double[] sortedValues, double percentile)
    {
        if (sortedValues.Length == 0)
        {
            return 0;
        }

        int index = (int)Math.Ceiling(percentile * sortedValues.Length) - 1;
        return sortedValues[Math.Clamp(index, 0, sortedValues.Length - 1)];
    }

    private static byte[] CreateDeterministicBytes(int length, byte seed)
    {
        byte[] payload = GC.AllocateUninitializedArray<byte>(length);
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)(seed + index));
        }

        return payload;
    }

    private static async Task ReadExactlyAndValidateAsync(
        Stream stream,
        byte[] buffer,
        ReadOnlyMemory<byte> expected,
        CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < expected.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, expected.Length - offset), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException($"The stream ended after {offset} of {expected.Length} bytes.");
            }

            offset += read;
        }

        if (!buffer.AsSpan(0, expected.Length).SequenceEqual(expected.Span))
        {
            throw new InvalidOperationException("The received payload did not match the expected bytes.");
        }

        if (await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false) != 0)
        {
            throw new InvalidOperationException("The stream exceeded the expected payload length.");
        }
    }

    private static void WriteUsage()
    {
        Console.Error.WriteLine(
            "Usage: --transport-loopback [--implementations incursa,systemnet] " +
            "[--scenarios download,upload,duplex] [--payload-sizes 1024,65536,1048576] " +
            "[--concurrency 1,4,16] [--samples 5] [--duration-seconds 2] " +
            "[--warmup-seconds 1] [--diagnostics true|false] [--label name] [--json path]");
    }

    private static string FormatImplementation(Implementation implementation) => implementation switch
    {
        Implementation.Incursa => "incursa",
        Implementation.SystemNet => "systemnet",
        _ => throw new ArgumentOutOfRangeException(nameof(implementation)),
    };

    private static string FormatScenario(Scenario scenario) => scenario switch
    {
        Scenario.Download => "download",
        Scenario.Upload => "upload",
        Scenario.Duplex => "duplex",
        _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
    };

    private interface IConnectedPair : IAsyncDisposable
    {
        string Name { get; }

        Task TransferAsync(
            Scenario scenario,
            byte[] requestPayload,
            byte[] responsePayload,
            byte[] requestBuffer,
            byte[] responseBuffer);
    }

    private sealed class IncursaConnectedPair(
        IncursaListener listener,
        IncursaClientConnection client,
        IncursaClientConnection server,
        CancellationTokenSource cancellationSource) : IConnectedPair
    {
        public string Name => "Incursa.Quic";

        public static async Task<IncursaConnectedPair> CreateAsync(
            SslServerAuthenticationOptions serverOptions,
            SslClientAuthenticationOptions clientOptions)
        {
            CancellationTokenSource cancellationSource = new(TimeSpan.FromMinutes(10));
            try
            {
                IPEndPoint listenEndPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
                IncursaListener listener = await IncursaListener.ListenAsync(
                    QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaListenerOptions(
                        listenEndPoint,
                        serverOptions),
                    cancellationSource.Token).ConfigureAwait(false);
                try
                {
                    Task<IncursaClientConnection> acceptTask = listener
                        .AcceptConnectionAsync(cancellationSource.Token).AsTask();
                    Task<IncursaClientConnection> connectTask = IncursaClientConnection.ConnectAsync(
                        QuicPublicApiLoopbackBenchmarkSupport.CreateIncursaClientOptions(
                            new IPEndPoint(IPAddress.Loopback, listenEndPoint.Port),
                            clientOptions),
                        cancellationSource.Token).AsTask();
                    await Task.WhenAll(acceptTask, connectTask).ConfigureAwait(false);
                    return new IncursaConnectedPair(
                        listener,
                        await connectTask.ConfigureAwait(false),
                        await acceptTask.ConfigureAwait(false),
                        cancellationSource);
                }
                catch
                {
                    await listener.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }
            catch
            {
                cancellationSource.Dispose();
                throw;
            }
        }

        public async Task TransferAsync(
            Scenario scenario,
            byte[] requestPayload,
            byte[] responsePayload,
            byte[] requestBuffer,
            byte[] responseBuffer)
        {
            CancellationToken token = cancellationSource.Token;
            Task<IncursaStream> acceptTask = server.AcceptInboundStreamAsync(token).AsTask();
            await Task.Yield();
            await using IncursaStream clientStream = await client.OpenOutboundStreamAsync(
                IncursaStreamType.Bidirectional,
                token).ConfigureAwait(false);
            ReadOnlyMemory<byte> initialPayload = scenario == Scenario.Download
                ? RequestMarker
                : requestPayload;
            Task clientWriteTask = WriteAndCompleteAsync(clientStream, initialPayload, token);
            await using IncursaStream serverStream = await acceptTask.ConfigureAwait(false);

            switch (scenario)
            {
                case Scenario.Download:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, RequestMarker, token)).ConfigureAwait(false);
                    await Task.WhenAll(
                        WriteAndCompleteAsync(serverStream, responsePayload, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, responsePayload, token)).ConfigureAwait(false);
                    break;

                case Scenario.Upload:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, requestPayload, token)).ConfigureAwait(false);
                    await Task.WhenAll(
                        WriteAndCompleteAsync(serverStream, ResponseMarker, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, ResponseMarker, token)).ConfigureAwait(false);
                    break;

                case Scenario.Duplex:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, requestPayload, token),
                        WriteAndCompleteAsync(serverStream, responsePayload, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, responsePayload, token))
                        .ConfigureAwait(false);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }

        }

        public async ValueTask DisposeAsync()
        {
            cancellationSource.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                await server.CloseAsync(0, cancellationSource.Token).ConfigureAwait(false);
                await client.CloseAsync(0, cancellationSource.Token).ConfigureAwait(false);
            }
            finally
            {
                await server.DisposeAsync().ConfigureAwait(false);
                await client.DisposeAsync().ConfigureAwait(false);
                await listener.DisposeAsync().ConfigureAwait(false);
                cancellationSource.Dispose();
            }
        }

        private static async Task WriteAndCompleteAsync(
            IncursaStream stream,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.CompleteWritesAsync(cancellationToken).ConfigureAwait(false);
            await stream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task ReadAndCloseAsync(
            IncursaStream stream,
            byte[] buffer,
            ReadOnlyMemory<byte> expected,
            CancellationToken cancellationToken)
        {
            await ReadExactlyAndValidateAsync(stream, buffer, expected, cancellationToken).ConfigureAwait(false);
            await stream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class SystemNetConnectedPair(
        SystemNetClientConnection client,
        SystemNetClientConnection server,
        CancellationTokenSource cancellationSource) : IConnectedPair
    {
        public string Name => "System.Net.Quic";

        public static async Task<SystemNetConnectedPair> CreateAsync(
            SslServerAuthenticationOptions serverOptions,
            SslClientAuthenticationOptions clientOptions)
        {
            CancellationTokenSource cancellationSource = new(TimeSpan.FromMinutes(10));
            try
            {
                (SystemNetClientConnection client, SystemNetClientConnection server) =
                    await QuicAllocationHarness.CreateSystemNetConnectedPairAsync(
                        serverOptions,
                        clientOptions).ConfigureAwait(false);
                return new SystemNetConnectedPair(
                    client,
                    server,
                    cancellationSource);
            }
            catch
            {
                cancellationSource.Dispose();
                throw;
            }
        }

        public async Task TransferAsync(
            Scenario scenario,
            byte[] requestPayload,
            byte[] responsePayload,
            byte[] requestBuffer,
            byte[] responseBuffer)
        {
            CancellationToken token = cancellationSource.Token;
            Task<SystemNetStream> acceptTask = server.AcceptInboundStreamAsync().AsTask();
            await Task.Yield();
            await using SystemNetStream clientStream = await client.OpenOutboundStreamAsync(
                SystemNetStreamType.Bidirectional).ConfigureAwait(false);
            ReadOnlyMemory<byte> initialPayload = scenario == Scenario.Download
                ? RequestMarker
                : requestPayload;
            Task clientWriteTask = WriteAndCompleteAsync(clientStream, initialPayload, token);
            await using SystemNetStream serverStream = await acceptTask.ConfigureAwait(false);

            switch (scenario)
            {
                case Scenario.Download:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, RequestMarker, token)).ConfigureAwait(false);
                    await Task.WhenAll(
                        WriteAndCompleteAsync(serverStream, responsePayload, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, responsePayload, token)).ConfigureAwait(false);
                    break;

                case Scenario.Upload:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, requestPayload, token)).ConfigureAwait(false);
                    await Task.WhenAll(
                        WriteAndCompleteAsync(serverStream, ResponseMarker, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, ResponseMarker, token)).ConfigureAwait(false);
                    break;

                case Scenario.Duplex:
                    await Task.WhenAll(
                        clientWriteTask,
                        ReadAndCloseAsync(serverStream, requestBuffer, requestPayload, token),
                        WriteAndCompleteAsync(serverStream, responsePayload, token),
                        ReadAndCloseAsync(clientStream, responseBuffer, responsePayload, token))
                        .ConfigureAwait(false);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }

        }

        public async ValueTask DisposeAsync()
        {
            cancellationSource.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                await server.CloseAsync(0, cancellationSource.Token).ConfigureAwait(false);
                await client.CloseAsync(0, cancellationSource.Token).ConfigureAwait(false);
            }
            finally
            {
                await server.DisposeAsync().ConfigureAwait(false);
                await client.DisposeAsync().ConfigureAwait(false);
                cancellationSource.Dispose();
            }
        }

        private static async Task WriteAndCompleteAsync(
            SystemNetStream stream,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            stream.CompleteWrites();
            await stream.WritesClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task ReadAndCloseAsync(
            SystemNetStream stream,
            byte[] buffer,
            ReadOnlyMemory<byte> expected,
            CancellationToken cancellationToken)
        {
            await ReadExactlyAndValidateAsync(stream, buffer, expected, cancellationToken).ConfigureAwait(false);
            await stream.ReadsClosed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private sealed class WorkerState(int requestSize, int responseSize)
    {
        public byte[] RequestBuffer { get; } = new byte[Math.Max(requestSize, 1)];

        public byte[] ResponseBuffer { get; } = new byte[Math.Max(responseSize, 1)];

        public List<double> LatenciesMilliseconds { get; } = [];
    }

    private sealed record WorkerResult(int Operations, int Failures, List<double> LatenciesMilliseconds);

    private sealed record SampleResult(
        int Operations,
        int Failures,
        double ElapsedMilliseconds,
        double OperationsPerSecond,
        double ThroughputBytesPerSecond,
        double ThroughputMebibytesPerSecond,
        double LatencyP50Milliseconds,
        double LatencyP95Milliseconds,
        double LatencyP99Milliseconds,
        long AllocatedBytes,
        double AllocatedBytesPerOperation,
        int Gen0Collections,
        int Gen1Collections,
        int Gen2Collections,
        bool MetricsInstrumentationEnabled,
        QuicRuntimeDiagnosticsResult? RuntimeDiagnostics);

    private sealed record ShapeResult(
        string Implementation,
        string Scenario,
        int PayloadSizeBytes,
        int Concurrency,
        double MedianThroughputMebibytesPerSecond,
        double MinimumThroughputMebibytesPerSecond,
        double MaximumThroughputMebibytesPerSecond,
        double ThroughputRangePercent,
        double ThroughputCoefficientOfVariationPercent,
        double MedianOperationsPerSecond,
        double MedianLatencyP50Milliseconds,
        double MedianLatencyP95Milliseconds,
        double MedianLatencyP99Milliseconds,
        double MedianAllocatedBytesPerOperation,
        int Failures,
        List<SampleResult> SampleResults);

    private sealed record HarnessResult(
        int SchemaVersion,
        string Label,
        DateTimeOffset StartedUtc,
        string Runtime,
        string OperatingSystem,
        int ProcessorCount,
        int DurationSeconds,
        int WarmupSeconds,
        int Samples,
        bool DiagnosticsEnabled,
        List<ShapeResult> Results);

    private sealed record Options(
        IReadOnlyList<Implementation> Implementations,
        IReadOnlyList<Scenario> Scenarios,
        IReadOnlyList<int> PayloadSizes,
        IReadOnlyList<int> ConcurrencyLevels,
        int Samples,
        int DurationSeconds,
        int WarmupSeconds,
        bool Diagnostics,
        string Label,
        string? JsonPath)
    {
        public static Options Parse(string[] args)
        {
            IReadOnlyList<Implementation> implementations = [Implementation.Incursa, Implementation.SystemNet];
            IReadOnlyList<Scenario> scenarios = [Scenario.Download, Scenario.Upload, Scenario.Duplex];
            IReadOnlyList<int> payloadSizes = [1024, 64 * 1024, 1024 * 1024];
            IReadOnlyList<int> concurrencyLevels = [1, 4, 16];
            int samples = 5;
            int durationSeconds = 2;
            int warmupSeconds = 1;
            bool diagnostics = false;
            string label = "local";
            string? jsonPath = null;

            for (int index = 0; index < args.Length; index++)
            {
                string option = args[index];
                string value = ReadValue(args, ref index, option);
                switch (option)
                {
                    case "--implementations":
                        implementations = ParseImplementations(value);
                        break;
                    case "--scenarios":
                        scenarios = ParseScenarios(value);
                        break;
                    case "--payload-sizes":
                        payloadSizes = ParsePositiveIntegers(value, option);
                        break;
                    case "--concurrency":
                        concurrencyLevels = ParsePositiveIntegers(value, option);
                        break;
                    case "--samples":
                        samples = ParsePositiveInteger(value, option);
                        break;
                    case "--duration-seconds":
                        durationSeconds = ParsePositiveInteger(value, option);
                        break;
                    case "--warmup-seconds":
                        warmupSeconds = ParsePositiveInteger(value, option);
                        break;
                    case "--diagnostics":
                        diagnostics = ParseBoolean(value, option);
                        break;
                    case "--label":
                        label = value;
                        break;
                    case "--json":
                        jsonPath = value;
                        break;
                    default:
                        throw new ArgumentException($"Unknown option '{option}'.");
                }
            }

            return new Options(
                implementations,
                scenarios,
                payloadSizes,
                concurrencyLevels,
                samples,
                durationSeconds,
                warmupSeconds,
                diagnostics,
                label,
                jsonPath);
        }

        private static string ReadValue(string[] args, ref int index, string option)
        {
            if (!option.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument '{option}'.");
            }

            if (index + 1 >= args.Length || args[index + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Option '{option}' requires a value.");
            }

            return args[++index];
        }

        private static IReadOnlyList<Implementation> ParseImplementations(string value)
        {
            List<Implementation> implementations = [];
            foreach (string item in Split(value))
            {
                implementations.Add(item.ToLowerInvariant() switch
                {
                    "incursa" => Implementation.Incursa,
                    "systemnet" => Implementation.SystemNet,
                    _ => throw new ArgumentException($"Unknown implementation '{item}'."),
                });
            }

            return implementations.Distinct().ToArray();
        }

        private static IReadOnlyList<Scenario> ParseScenarios(string value)
        {
            List<Scenario> scenarios = [];
            foreach (string item in Split(value))
            {
                scenarios.Add(item.ToLowerInvariant() switch
                {
                    "download" => Scenario.Download,
                    "upload" => Scenario.Upload,
                    "duplex" => Scenario.Duplex,
                    _ => throw new ArgumentException($"Unknown scenario '{item}'."),
                });
            }

            return scenarios.Distinct().ToArray();
        }

        private static IReadOnlyList<int> ParsePositiveIntegers(string value, string option)
            => Split(value).Select(item => ParsePositiveInteger(item, option)).Distinct().ToArray();

        private static int ParsePositiveInteger(string value, string option)
        {
            int parsed = int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);
            if (parsed <= 0)
            {
                throw new ArgumentException($"Option '{option}' values must be positive.");
            }

            return parsed;
        }

        private static bool ParseBoolean(string value, string option)
            => bool.TryParse(value, out bool parsed)
                ? parsed
                : throw new ArgumentException($"Option '{option}' must be true or false.");

        private static string[] Split(string value)
        {
            string[] values = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (values.Length == 0)
            {
                throw new ArgumentException("Comma-separated option values cannot be empty.");
            }

            return values;
        }
    }

    private enum Implementation
    {
        Incursa,
        SystemNet,
    }

    private enum Scenario
    {
        Download,
        Upload,
        Duplex,
    }
}
