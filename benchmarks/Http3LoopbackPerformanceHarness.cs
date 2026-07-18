// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Incursa.Qpack;
using Incursa.Quic.Http3;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Runs repeated, exact HTTP/3 loopback downloads without ProtocolLab orchestration.
/// </summary>
[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class Http3LoopbackPerformanceHarness
{
    private const int StreamingChunkSize = 16 * 1024;
    private static readonly byte[] UploadResponseBody = "ok"u8.ToArray();
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

        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            Console.Error.WriteLine("Incursa.Quic loopback support is unavailable on this platform.");
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

        return result.Results.All(static item => item.Failures == 0) ? 0 : 1;
    }

    private static async Task<HarnessResult> RunMatrixAsync(Options options)
    {
        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        List<ShapeResult> results = [];
        foreach (int payloadSize in options.PayloadSizes)
        {
            byte[] expectedBody = CreateDeterministicBytes(payloadSize);
            foreach (ScenarioKind scenario in options.Scenarios)
            {
                await using LoopbackServer server = await LoopbackServer.StartAsync(scenario, expectedBody).ConfigureAwait(false);

                foreach (int concurrency in options.ConcurrencyLevels)
                {
                    await RunSampleAsync(
                        server,
                        concurrency,
                        TimeSpan.FromSeconds(options.WarmupSeconds),
                        collectMetrics: false).ConfigureAwait(false);

                    List<SampleResult> samples = new(options.Samples);
                    for (int sampleIndex = 0; sampleIndex < options.Samples; sampleIndex++)
                    {
                        GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: false);
                        GC.WaitForPendingFinalizers();
                        samples.Add(await RunSampleAsync(
                            server,
                            concurrency,
                            TimeSpan.FromSeconds(options.DurationSeconds),
                            collectMetrics: true).ConfigureAwait(false));
                    }

                    results.Add(Summarize(scenario, payloadSize, concurrency, samples));
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
            Results: results);
    }

    private static async Task<SampleResult> RunSampleAsync(
        LoopbackServer server,
        int concurrency,
        TimeSpan duration,
        bool collectMetrics)
    {
        WorkerState[] workerStates = new WorkerState[concurrency];
        for (int workerIndex = 0; workerIndex < workerStates.Length; workerIndex++)
        {
            workerStates[workerIndex] = new WorkerState(server.ExpectedResponseBody.Length);
        }

        long allocatedBefore = collectMetrics ? GC.GetTotalAllocatedBytes(precise: true) : 0;
        int gen0Before = collectMetrics ? GC.CollectionCount(0) : 0;
        int gen1Before = collectMetrics ? GC.CollectionCount(1) : 0;
        int gen2Before = collectMetrics ? GC.CollectionCount(2) : 0;
        long started = Stopwatch.GetTimestamp();
        long deadline = started + (long)(duration.TotalSeconds * Stopwatch.Frequency);

        Task<WorkerResult>[] workers = new Task<WorkerResult>[concurrency];
        for (int workerIndex = 0; workerIndex < workers.Length; workerIndex++)
        {
            workers[workerIndex] = RunWorkerAsync(server, deadline, workerStates[workerIndex]);
        }

        WorkerResult[] workerResults = await Task.WhenAll(workers).ConfigureAwait(false);
        TimeSpan elapsed = Stopwatch.GetElapsedTime(started);
        long allocatedAfter = collectMetrics ? GC.GetTotalAllocatedBytes(precise: true) : 0;

        int requests = workerResults.Sum(static item => item.Requests);
        int failures = workerResults.Sum(static item => item.Failures);
        double[] latencies = workerResults.SelectMany(static item => item.LatenciesMilliseconds).ToArray();
        Array.Sort(latencies);
        double elapsedSeconds = elapsed.TotalSeconds;
        double throughputBytesPerSecond = requests * (double)server.TransferredBytesPerRequest / elapsedSeconds;

        return new SampleResult(
            Requests: requests,
            Failures: failures,
            ElapsedMilliseconds: elapsed.TotalMilliseconds,
            RequestsPerSecond: requests / elapsedSeconds,
            ThroughputBytesPerSecond: throughputBytesPerSecond,
            ThroughputMebibytesPerSecond: throughputBytesPerSecond / (1024 * 1024),
            LatencyP50Milliseconds: Percentile(latencies, 0.50),
            LatencyP95Milliseconds: Percentile(latencies, 0.95),
            LatencyP99Milliseconds: Percentile(latencies, 0.99),
            AllocatedBytes: collectMetrics ? allocatedAfter - allocatedBefore : 0,
            AllocatedBytesPerRequest: collectMetrics && requests > 0 ? (allocatedAfter - allocatedBefore) / (double)requests : 0,
            Gen0Collections: collectMetrics ? GC.CollectionCount(0) - gen0Before : 0,
            Gen1Collections: collectMetrics ? GC.CollectionCount(1) - gen1Before : 0,
            Gen2Collections: collectMetrics ? GC.CollectionCount(2) - gen2Before : 0);
    }

    private static async Task<WorkerResult> RunWorkerAsync(
        LoopbackServer server,
        long deadline,
        WorkerState state)
    {
        byte[] receivedBody = state.ReceivedBody;
        List<double> latencies = state.LatenciesMilliseconds;
        int requests = 0;
        int failures = 0;

        do
        {
            long requestStarted = Stopwatch.GetTimestamp();
            try
            {
                using HttpRequestMessage request = new(server.Method, server.RequestUri)
                {
                    Version = HttpVersion.Version30,
                    VersionPolicy = HttpVersionPolicy.RequestVersionExact,
                };
                if (server.RequestBody is not null)
                {
                    request.Content = new ByteArrayContent(server.RequestBody);
                }

                using HttpResponseMessage response = await server.Client.SendAsync(
                    request,
                    HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

                if (response.StatusCode != HttpStatusCode.OK || response.Version != HttpVersion.Version30)
                {
                    throw new InvalidOperationException(
                        $"Unexpected response status/version: {(int)response.StatusCode}/{response.Version}.");
                }

                if (response.Content.Headers.ContentLength != server.ExpectedResponseBody.Length)
                {
                    throw new InvalidOperationException(
                        $"Unexpected content length: {response.Content.Headers.ContentLength}.");
                }

                await using Stream content = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
                await ReadExactlyAsync(content, receivedBody).ConfigureAwait(false);
                if (await content.ReadAsync(receivedBody.AsMemory(0, 1)).ConfigureAwait(false) != 0)
                {
                    throw new InvalidOperationException("The response exceeded its declared content length.");
                }

                if (!receivedBody.AsSpan().SequenceEqual(server.ExpectedResponseBody))
                {
                    throw new InvalidOperationException("The response payload did not match the expected bytes.");
                }

                requests++;
                latencies.Add(Stopwatch.GetElapsedTime(requestStarted).TotalMilliseconds);
            }
            catch (Exception exception)
            {
                failures++;
                throw new InvalidOperationException(
                    $"HTTP/3 loopback request failed after {requests} successful requests.",
                    exception);
            }
        }
        while (Stopwatch.GetTimestamp() < deadline);

        return new WorkerResult(requests, failures, latencies);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> destination)
    {
        int offset = 0;
        while (offset < destination.Length)
        {
            int bytesRead = await stream.ReadAsync(destination[offset..]).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                throw new EndOfStreamException(
                    $"The response ended after {offset} of {destination.Length} expected bytes.");
            }

            offset += bytesRead;
        }
    }

    private static ShapeResult Summarize(
        ScenarioKind scenario,
        int payloadSize,
        int concurrency,
        List<SampleResult> samples)
    {
        double[] throughputs = samples.Select(static item => item.ThroughputMebibytesPerSecond).Order().ToArray();
        double mean = throughputs.Average();
        double variance = throughputs.Sum(value => Math.Pow(value - mean, 2)) / throughputs.Length;
        double standardDeviation = Math.Sqrt(variance);
        int failures = samples.Sum(static item => item.Failures);

        return new ShapeResult(
            Scenario: GetScenarioName(scenario),
            PayloadSizeBytes: payloadSize,
            Concurrency: concurrency,
            MedianThroughputMebibytesPerSecond: Percentile(throughputs, 0.50),
            MinimumThroughputMebibytesPerSecond: throughputs[0],
            MaximumThroughputMebibytesPerSecond: throughputs[^1],
            ThroughputRangePercent: mean == 0 ? 0 : (throughputs[^1] - throughputs[0]) / mean * 100,
            ThroughputCoefficientOfVariationPercent: mean == 0 ? 0 : standardDeviation / mean * 100,
            MedianRequestsPerSecond: Percentile(samples.Select(static item => item.RequestsPerSecond).Order().ToArray(), 0.50),
            MedianLatencyP95Milliseconds: Percentile(samples.Select(static item => item.LatencyP95Milliseconds).Order().ToArray(), 0.50),
            MedianAllocatedBytesPerRequest: Percentile(samples.Select(static item => item.AllocatedBytesPerRequest).Order().ToArray(), 0.50),
            Failures: failures,
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

    private static byte[] CreateDeterministicBytes(int length)
    {
        byte[] payload = GC.AllocateUninitializedArray<byte>(length);
        for (int index = 0; index < payload.Length; index++)
        {
            payload[index] = unchecked((byte)index);
        }

        return payload;
    }

    private static void WriteUsage()
    {
        Console.Error.WriteLine(
            "Usage: --http3-loopback [--scenarios fixed,streaming,upload,duplex] " +
            "[--payload-sizes 1024,65536,1048576] [--concurrency 1,4,16] " +
            "[--samples 5] [--duration-seconds 3] [--warmup-seconds 1] [--label name] [--json path]");
    }

    private static string GetScenarioName(ScenarioKind scenario) => scenario switch
    {
        ScenarioKind.FixedDownload => "fixed",
        ScenarioKind.StreamingDownload => "streaming",
        ScenarioKind.Upload => "upload",
        ScenarioKind.Duplex => "duplex",
        _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
    };

    private sealed class FixedBodyHandler(byte[] body) : IHttp3RequestHandler
    {
        private readonly Http3ServerResponse response = Http3ServerResponse.CreateFromImmutableBodyAndHeaders(
            200,
            body,
            BuildBinaryHeaders(body.Length));

        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
        {
            _ = request;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(response);
        }
    }

    private sealed class StreamingBodyHandler(byte[] body) : IHttp3RequestHandler
    {
        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
        {
            _ = request;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Http3ServerResponse.CreateStreaming(
                200,
                StreamBodyAsync(body, cancellationToken),
                BuildBinaryHeaders(body.Length),
                dataFramePayloadSize: StreamingChunkSize));
        }
    }

    private sealed class UploadHandler(byte[] expectedBody) : IHttp3RequestHandler
    {
        private readonly Http3ServerResponse response = Http3ServerResponse.CreateFromImmutableBodyAndHeaders(
            200,
            UploadResponseBody,
            BuildBinaryHeaders(UploadResponseBody.Length));

        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!request.Body.Span.SequenceEqual(expectedBody))
            {
                throw new InvalidOperationException("The uploaded request body did not match the expected bytes.");
            }

            return ValueTask.FromResult(response);
        }
    }

    private sealed class DuplexHandler : IHttp3RequestHandler, IHttp3StreamingRequestHandler
    {
        public bool CanHandleStreaming(Http3StreamingRequest request)
            => request.Path == "/duplex";

        public bool RetainStreamingRequestBodyChunks(Http3StreamingRequest request)
            => false;

        public ValueTask<Http3ServerResponse> HandleAsync(
            Http3Request request,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The duplex workload must use the streaming request path.");

        public ValueTask<Http3ServerResponse> HandleStreamingAsync(
            Http3StreamingRequest request,
            CancellationToken cancellationToken = default)
        {
            int contentLength = int.Parse(
                request.Headers.First(static header => header.Name == "content-length").Value,
                NumberStyles.None,
                CultureInfo.InvariantCulture);
            return ValueTask.FromResult(Http3ServerResponse.CreateStreaming(
                200,
                EchoBodyAsync(request.Body, cancellationToken),
                BuildBinaryHeaders(contentLength),
                dataFramePayloadSize: StreamingChunkSize));
        }
    }

    private static QPackFieldLine[] BuildBinaryHeaders(int contentLength) =>
    [
        new QPackFieldLine("content-type", "application/octet-stream"),
        new QPackFieldLine("content-length", contentLength.ToString(CultureInfo.InvariantCulture)),
        new QPackFieldLine("server", "Incursa.Quic.Http3"),
    ];

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> StreamBodyAsync(
        byte[] body,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        for (int offset = 0; offset < body.Length; offset += StreamingChunkSize)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return body.AsMemory(offset, Math.Min(StreamingChunkSize, body.Length - offset));
        }
    }

    private static async IAsyncEnumerable<ReadOnlyMemory<byte>> EchoBodyAsync(
        IAsyncEnumerable<ReadOnlyMemory<byte>> requestBody,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (ReadOnlyMemory<byte> chunk in requestBody.WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            yield return chunk;
        }
    }

    private sealed class LoopbackServer : IAsyncDisposable
    {
        private readonly X509Certificate2 certificate;
        private readonly Http3Server server;
        private readonly CancellationTokenSource shutdown;
        private readonly Task serverTask;

        private LoopbackServer(
            X509Certificate2 certificate,
            Http3Server server,
            CancellationTokenSource shutdown,
            Task serverTask,
            IPEndPoint endPoint,
            HttpClient client,
            ScenarioKind scenario,
            byte[] payload)
        {
            this.certificate = certificate;
            this.server = server;
            this.shutdown = shutdown;
            this.serverTask = serverTask;
            Client = client;
            Method = scenario is ScenarioKind.Upload or ScenarioKind.Duplex ? HttpMethod.Post : HttpMethod.Get;
            string path = scenario switch
            {
                ScenarioKind.FixedDownload => "/fixed",
                ScenarioKind.StreamingDownload => "/streaming",
                ScenarioKind.Upload => "/upload",
                ScenarioKind.Duplex => "/duplex",
                _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
            };
            RequestUri = new Uri($"https://127.0.0.1:{endPoint.Port}{path}");
            RequestBody = scenario is ScenarioKind.Upload or ScenarioKind.Duplex ? payload : null;
            ExpectedResponseBody = scenario == ScenarioKind.Upload ? UploadResponseBody : payload;
            TransferredBytesPerRequest = scenario == ScenarioKind.Duplex
                ? checked(payload.Length * 2)
                : payload.Length;
        }

        internal HttpClient Client { get; }

        internal byte[] ExpectedResponseBody { get; }

        internal HttpMethod Method { get; }

        internal byte[]? RequestBody { get; }

        internal Uri RequestUri { get; }

        internal int TransferredBytesPerRequest { get; }

        internal static async Task<LoopbackServer> StartAsync(ScenarioKind scenario, byte[] payload)
        {
            X509Certificate2 certificate = QuicPublicApiLoopbackBenchmarkSupport.CreateServerCertificate();
            IPEndPoint endPoint = QuicPublicApiLoopbackBenchmarkSupport.GetUnusedLoopbackEndPoint();
            SslServerAuthenticationOptions authenticationOptions =
                QuicPublicApiLoopbackBenchmarkSupport.CreateServerAuthenticationOptions(certificate);
            QuicServerConnectionOptions serverOptions = new()
            {
                DefaultCloseErrorCode = 0,
                DefaultStreamErrorCode = 0,
                IdleTimeout = TimeSpan.FromMinutes(5),
                KeepAliveInterval = TimeSpan.FromSeconds(30),
                MaxInboundBidirectionalStreams = 512,
                MaxInboundUnidirectionalStreams = 16,
                InitialReceiveWindowSizes = new QuicReceiveWindowSizes
                {
                    Connection = 16 * 1024 * 1024,
                    LocallyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                    RemotelyInitiatedBidirectionalStream = 16 * 1024 * 1024,
                    UnidirectionalStream = 16 * 1024 * 1024,
                },
                ServerAuthenticationOptions = authenticationOptions,
            };
            QuicListenerOptions listenerOptions = new()
            {
                ListenEndPoint = endPoint,
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ListenBacklog = 16,
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(serverOptions),
            };

            IHttp3RequestHandler handler = scenario switch
            {
                ScenarioKind.FixedDownload => new FixedBodyHandler(payload),
                ScenarioKind.StreamingDownload => new StreamingBodyHandler(payload),
                ScenarioKind.Upload => new UploadHandler(payload),
                ScenarioKind.Duplex => new DuplexHandler(),
                _ => throw new ArgumentOutOfRangeException(nameof(scenario)),
            };
            Http3Server server = await Http3Server.ListenAsync(listenerOptions, handler).ConfigureAwait(false);
            CancellationTokenSource shutdown = new(TimeSpan.FromMinutes(10));
            Task serverTask = server.ServeAsync(shutdown.Token);
            SocketsHttpHandler socketsHandler = new()
            {
                EnableMultipleHttp3Connections = true,
                SslOptions = new SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                },
            };
            HttpClient client = new(socketsHandler)
            {
                Timeout = TimeSpan.FromSeconds(30),
            };
            return new LoopbackServer(certificate, server, shutdown, serverTask, endPoint, client, scenario, payload);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            shutdown.Cancel();
            await server.DisposeAsync().ConfigureAwait(false);
            await serverTask.WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);
            shutdown.Dispose();
            certificate.Dispose();
        }
    }

    private sealed record Options(
        ScenarioKind[] Scenarios,
        int[] PayloadSizes,
        int[] ConcurrencyLevels,
        int Samples,
        int DurationSeconds,
        int WarmupSeconds,
        string Label,
        string? JsonPath)
    {
        internal static Options Parse(string[] args)
        {
            Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
            for (int index = 0; index < args.Length; index += 2)
            {
                if (index + 1 >= args.Length || !args[index].StartsWith("--", StringComparison.Ordinal))
                {
                    throw new ArgumentException($"Expected a value after '{args[index]}'.");
                }

                values[args[index]] = args[index + 1];
            }

            ScenarioKind[] scenarios = ParseScenarios(values.GetValueOrDefault("--scenarios", "fixed"));
            int[] payloadSizes = ParsePositiveList(values.GetValueOrDefault("--payload-sizes", "1024,65536,1048576"), "payload sizes");
            int[] concurrency = ParsePositiveList(values.GetValueOrDefault("--concurrency", "1,4,16"), "concurrency");
            int samples = ParsePositive(values.GetValueOrDefault("--samples", "5"), "samples");
            int durationSeconds = ParsePositive(values.GetValueOrDefault("--duration-seconds", "3"), "duration seconds");
            int warmupSeconds = ParsePositive(values.GetValueOrDefault("--warmup-seconds", "1"), "warmup seconds");
            string label = values.GetValueOrDefault("--label", "local");
            string? jsonPath = values.GetValueOrDefault("--json");

            string[] known = [
                "--scenarios", "--payload-sizes", "--concurrency", "--samples", "--duration-seconds",
                "--warmup-seconds", "--label", "--json",
            ];
            string? unknown = values.Keys.FirstOrDefault(key => !known.Contains(key, StringComparer.OrdinalIgnoreCase));
            if (unknown is not null)
            {
                throw new ArgumentException($"Unknown option '{unknown}'.");
            }

            return new Options(scenarios, payloadSizes, concurrency, samples, durationSeconds, warmupSeconds, label, jsonPath);
        }

        private static ScenarioKind[] ParseScenarios(string value)
        {
            ScenarioKind[] parsed = value
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(static item => item.ToLowerInvariant() switch
                {
                    "fixed" => ScenarioKind.FixedDownload,
                    "streaming" => ScenarioKind.StreamingDownload,
                    "upload" => ScenarioKind.Upload,
                    "duplex" => ScenarioKind.Duplex,
                    _ => throw new ArgumentException($"Unknown HTTP/3 loopback scenario '{item}'."),
                })
                .Distinct()
                .ToArray();
            if (parsed.Length == 0)
            {
                throw new ArgumentException("At least one HTTP/3 loopback scenario is required.");
            }

            return parsed;
        }

        private static int[] ParsePositiveList(string value, string name)
        {
            int[] parsed = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(item => ParsePositive(item, name))
                .Distinct()
                .ToArray();
            if (parsed.Length == 0)
            {
                throw new ArgumentException($"At least one {name} value is required.");
            }

            return parsed;
        }

        private static int ParsePositive(string value, string name)
        {
            int parsed = int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture);
            if (parsed <= 0)
            {
                throw new ArgumentOutOfRangeException(name, parsed, $"{name} must be positive.");
            }

            return parsed;
        }
    }

    private sealed record WorkerResult(int Requests, int Failures, List<double> LatenciesMilliseconds);

    private sealed class WorkerState(int responseBodyLength)
    {
        internal List<double> LatenciesMilliseconds { get; } = new(capacity: 1024);

        internal byte[] ReceivedBody { get; } = GC.AllocateUninitializedArray<byte>(responseBodyLength);
    }

    private enum ScenarioKind
    {
        FixedDownload,
        StreamingDownload,
        Upload,
        Duplex,
    }

    private sealed record SampleResult(
        int Requests,
        int Failures,
        double ElapsedMilliseconds,
        double RequestsPerSecond,
        double ThroughputBytesPerSecond,
        double ThroughputMebibytesPerSecond,
        double LatencyP50Milliseconds,
        double LatencyP95Milliseconds,
        double LatencyP99Milliseconds,
        long AllocatedBytes,
        double AllocatedBytesPerRequest,
        int Gen0Collections,
        int Gen1Collections,
        int Gen2Collections);

    private sealed record ShapeResult(
        string Scenario,
        int PayloadSizeBytes,
        int Concurrency,
        double MedianThroughputMebibytesPerSecond,
        double MinimumThroughputMebibytesPerSecond,
        double MaximumThroughputMebibytesPerSecond,
        double ThroughputRangePercent,
        double ThroughputCoefficientOfVariationPercent,
        double MedianRequestsPerSecond,
        double MedianLatencyP95Milliseconds,
        double MedianAllocatedBytesPerRequest,
        int Failures,
        IReadOnlyList<SampleResult> SampleResults);

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
        IReadOnlyList<ShapeResult> Results);
}
