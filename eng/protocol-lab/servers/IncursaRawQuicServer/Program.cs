// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Channels;
using Incursa.Quic;

var port = args.Length > 0 && int.TryParse(args[0], out var parsedPort) ? parsedPort : 0;
var listenPort = port > 0 ? port : GetFreePort();
var bindAddressText = Environment.GetEnvironmentVariable("PROTOCOL_LAB_TARGET_BIND_ADDRESS") ?? "127.0.0.1";
if (!IPAddress.TryParse(bindAddressText, out var bindAddress))
{
    throw new InvalidOperationException($"PROTOCOL_LAB_TARGET_BIND_ADDRESS is not a valid IP address: {bindAddressText}");
}

var advertisedHost = Environment.GetEnvironmentVariable("PROTOCOL_LAB_TARGET_ADVERTISE_HOST");
if (string.IsNullOrWhiteSpace(advertisedHost))
{
    advertisedHost = bindAddress.Equals(IPAddress.Any) ? "127.0.0.1" : bindAddress.ToString();
}

var alpn = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_ALPN") ?? "plab-raw-quic";
var certSubject = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_CERT_SUBJECT") ?? "CN=Incursa-RawQuic-Local";
var payloadDirection = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_DIRECTION") ?? "bidirectional";
var behavior = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_BEHAVIOR");
var payloadSizeText = Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_SIZE_BYTES");
var adaptiveRuntimePolicy = ResolveAdaptiveRuntimePolicy(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY"));
var applicationSendTurnPolicy = ResolveApplicationSendTurnPolicy(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY"));
var applicationSendBatchPolicy = ResolveApplicationSendBatchPolicy(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_BATCH_POLICY"));
var queuedSendBurstPolicy = ResolveQueuedSendBurstPolicy(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_BURST_POLICY"));
var oversizedWriteAdmissionPolicy = ResolveOversizedWriteAdmissionPolicy(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_OVERSIZED_WRITE_ADMISSION_POLICY"));
var stage1AxisSelected =
    applicationSendTurnPolicy.ForcedMode is not null
    || applicationSendTurnPolicy.ObservationMode != QuicApplicationSendTurnObservationMode.Disabled
    || applicationSendBatchPolicy.ForcedMode is not null
    || applicationSendBatchPolicy.ObservationMode != QuicApplicationSendBatchObservationMode.Disabled
    || queuedSendBurstPolicy.ForcedMode is not null
    || queuedSendBurstPolicy.ObservationMode != QuicQueuedSendBurstObservationMode.Disabled
    || oversizedWriteAdmissionPolicy.ForcedMode is not null
    || oversizedWriteAdmissionPolicy.ObservationMode != QuicOversizedWriteAdmissionObservationMode.Disabled;
var forcedStage1AxisCount =
    (applicationSendTurnPolicy.ForcedMode is null ? 0 : 1)
    + (applicationSendBatchPolicy.ForcedMode is null ? 0 : 1)
    + (queuedSendBurstPolicy.ForcedMode is null ? 0 : 1)
    + (oversizedWriteAdmissionPolicy.ForcedMode is null ? 0 : 1);
if (forcedStage1AxisCount > 1)
{
    throw new InvalidOperationException(
        "Only one Stage 1 adaptive-runtime policy axis can be forced by a raw QUIC host process.");
}

if (stage1AxisSelected
    && adaptiveRuntimePolicy.ForcedMode is not null
    and not QuicReceiveCreditPolicyMode.LegacyCurrent)
{
    throw new InvalidOperationException(
        "Stage 1 send-path evidence requires receive_credit_publication=legacy_current.");
}

var adaptiveInstrumentationEnabled =
    adaptiveRuntimePolicy.ForcedMode is not null
    || adaptiveRuntimePolicy.ShadowEnabled
    || stage1AxisSelected;
var sendTurnObservationMode = adaptiveInstrumentationEnabled
    ? EnableUnifiedSendTurnObservation(applicationSendTurnPolicy.ObservationMode)
    : applicationSendTurnPolicy.ObservationMode;
var sendBatchObservationMode = adaptiveInstrumentationEnabled
    ? EnableUnifiedSendBatchObservation(applicationSendBatchPolicy.ObservationMode)
    : applicationSendBatchPolicy.ObservationMode;
var burstObservationMode = adaptiveInstrumentationEnabled
    ? EnableUnifiedBurstObservation(queuedSendBurstPolicy.ObservationMode)
    : queuedSendBurstPolicy.ObservationMode;
var oversizedObservationMode = adaptiveInstrumentationEnabled
    ? EnableUnifiedOversizedObservation(oversizedWriteAdmissionPolicy.ObservationMode)
    : oversizedWriteAdmissionPolicy.ObservationMode;
QuicAdaptiveRuntimeStage1PolicySnapshot? configuredStage1Policy =
    adaptiveInstrumentationEnabled
        ? QuicAdaptiveRuntimeStage1ConfiguredPolicy.Create(
            applicationSendTurnPolicy.ForcedMode,
            sendTurnObservationMode,
            applicationSendBatchPolicy.ForcedMode,
            sendBatchObservationMode,
            queuedSendBurstPolicy.ForcedMode,
            burstObservationMode,
            oversizedWriteAdmissionPolicy.ForcedMode,
            oversizedObservationMode)
        : null;
var epochPublisher = adaptiveInstrumentationEnabled
    ? new AdaptiveRuntimeEpochPublisher(configuredStage1Policy)
    : null;
var echoResponses = string.Equals(payloadDirection, "bidirectional", StringComparison.OrdinalIgnoreCase);
var downloadPayload = string.Equals(payloadDirection, "server-to-client", StringComparison.OrdinalIgnoreCase)
    ? CreateDownloadPayload(payloadSizeText)
    : null;
var downloadWriteSizeBytes = ResolveDownloadWriteSizeBytes(behavior, downloadPayload);
const int RawQuicConcurrentBidirectionalStreamLimit = 256;
const int RawQuicReceiveWindowBytes = 16 * 1024 * 1024;
const int RawQuicEchoBufferBytes = 64 * 1024;
const int RawQuicDownloadChunkBytes = 64 * 1024;
const int SmallApplicationWriteSizeBytes = 1024;
const int SmallSustainedDownloadPayloadLength = 4 * 1024 * 1024;
const int FixedTotalSmallSustainedDownloadPayloadLength = 16 * 1024 * 1024;
const string SmallSustainedDownloadBehavior = "sustained-download-4096x1kb";
const string FixedTotalSmallSustainedDownloadBehavior = "sustained-download-16384x1kb";
const string DownloadRequestMagic = "PLAB-DL1";
const int DownloadRequestLength = 16;
const int MaximumDownloadPayloadLength = 64 * 1024 * 1024;
var boundedFinalEchoBytes = ResolveBoundedFinalEchoBytes(echoResponses, behavior, payloadSizeText);

var certificate = GenerateSelfSignedCertificate(certSubject);
var alpnProtocol = new SslApplicationProtocol(alpn);
var debugLogging = string.Equals(Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_DEBUG"), "1", StringComparison.Ordinal);
var summaryLogging = debugLogging
    || string.Equals(Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_SUMMARY"), "1", StringComparison.Ordinal);
var capacitySummaryLogging = string.Equals(
    Environment.GetEnvironmentVariable("PROTOCOL_LAB_INCURSA_RAW_QUIC_CAPACITY_SUMMARY"),
    "1",
    StringComparison.Ordinal);
var connectionCount = 0;

var listenerOptions = new QuicListenerOptions
{
    ListenEndPoint = new IPEndPoint(bindAddress, listenPort),
    ApplicationProtocols = [alpnProtocol],
    ConnectionOptionsCallback = (_, _, _) =>
    {
        var connectionSinks = epochPublisher?.CreateConnectionSinks();
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer accepted handshake proposal for ALPN '{alpn}'");
        }

        return ValueTask.FromResult(new QuicServerConnectionOptions
        {
            DefaultStreamErrorCode = 0,
            DefaultCloseErrorCode = 0,
            MaxInboundBidirectionalStreams = RawQuicConcurrentBidirectionalStreamLimit,
            InitialReceiveWindowSizes = new QuicReceiveWindowSizes
            {
                Connection = RawQuicReceiveWindowBytes,
                LocallyInitiatedBidirectionalStream = RawQuicReceiveWindowBytes,
                RemotelyInitiatedBidirectionalStream = RawQuicReceiveWindowBytes,
                UnidirectionalStream = RawQuicReceiveWindowBytes,
            },
            ForcedReceiveCreditPolicyMode = stage1AxisSelected
                ? QuicReceiveCreditPolicyMode.LegacyCurrent
                : adaptiveRuntimePolicy.ForcedMode,
            ForcedApplicationSendTurnPolicyMode = applicationSendTurnPolicy.ForcedMode,
            ForcedApplicationSendBatchPolicyMode = applicationSendBatchPolicy.ForcedMode,
            ForcedQueuedSendBurstPolicyMode = queuedSendBurstPolicy.ForcedMode,
            ForcedOversizedWriteAdmissionPolicyMode =
                oversizedWriteAdmissionPolicy.ForcedMode,
            AdaptiveRuntimeShadowEnabled = adaptiveInstrumentationEnabled,
            AdaptiveRuntimeShadowEpochInterval = !adaptiveInstrumentationEnabled
                ? TimeSpan.Zero
                : TimeSpan.FromMilliseconds(250),
            AdaptiveRuntimeShadowEpochSink = !adaptiveInstrumentationEnabled
                ? null
                : connectionSinks?.EpochSink,
            ApplicationSendTurnPolicyProvenanceSink = applicationSendTurnPolicy.ForcedMode is null
                ? null
                : connectionSinks?.ApplicationSendTurnPolicySink,
            ApplicationSendTurnObservationMode = sendTurnObservationMode,
            ApplicationSendTurnEvidenceSink =
                sendTurnObservationMode == QuicApplicationSendTurnObservationMode.Disabled
                    ? null
                    : connectionSinks?.ApplicationSendTurnEvidenceSink,
            ApplicationSendBatchObservationMode = sendBatchObservationMode,
            ApplicationSendBatchEvidenceSink =
                sendBatchObservationMode == QuicApplicationSendBatchObservationMode.Disabled
                    ? null
                    : connectionSinks?.ApplicationSendBatchEvidenceSink,
            QueuedSendBurstObservationMode = burstObservationMode,
            QueuedSendBurstEvidenceSink =
                burstObservationMode == QuicQueuedSendBurstObservationMode.Disabled
                    ? null
                    : connectionSinks?.QueuedSendBurstEvidenceSink,
            OversizedWriteAdmissionObservationMode = oversizedObservationMode,
            OversizedWriteAdmissionEvidenceSink =
                oversizedObservationMode == QuicOversizedWriteAdmissionObservationMode.Disabled
                    ? null
                    : connectionSinks?.OversizedWriteAdmissionEvidenceSink,
            ActorServiceObservationMode = adaptiveInstrumentationEnabled
                ? QuicActorServiceObservationMode.ObserveOnly
                : QuicActorServiceObservationMode.Disabled,
            ActorServiceEvidenceSink = adaptiveInstrumentationEnabled
                ? connectionSinks?.ActorServiceEvidenceSink
                : null,
            BufferCopyObservationMode = adaptiveInstrumentationEnabled
                ? QuicBufferCopyObservationMode.ObserveOnly
                : QuicBufferCopyObservationMode.Disabled,
            BufferCopyEvidenceSink = adaptiveInstrumentationEnabled
                ? connectionSinks?.BufferCopyEvidenceSink
                : null,
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = certificate,
                ApplicationProtocols = [alpnProtocol],
                EnabledSslProtocols = SslProtocols.Tls13,
                EncryptionPolicy = EncryptionPolicy.RequireEncryption
            }
        });
    }
};

var listener = await QuicListener.ListenAsync(listenerOptions);

Console.Error.WriteLine($"IncursaRawQuicServer listening on {bindAddress}:{listenPort} with ALPN '{alpn}'");
Console.WriteLine($"QUIC_ENDPOINT={advertisedHost}:{listenPort}");
Console.WriteLine($"QUIC_PORT={listenPort}");
Console.WriteLine($"QUIC_ALPN={alpn}");
Console.WriteLine($"QUIC_IMPLEMENTATION=incursa-raw-quic");
Console.WriteLine(
    $"QUIC_RECEIVE_CREDIT_POLICY={(stage1AxisSelected ? "legacy_current" : adaptiveRuntimePolicy.Name)}");
Console.WriteLine($"QUIC_APPLICATION_SEND_TURN_POLICY={applicationSendTurnPolicy.Name}");
Console.WriteLine($"QUIC_APPLICATION_SEND_BATCH_POLICY={applicationSendBatchPolicy.Name}");
Console.WriteLine($"QUIC_QUEUED_SEND_BURST_POLICY={queuedSendBurstPolicy.Name}");
Console.WriteLine($"QUIC_OVERSIZED_WRITE_ADMISSION_POLICY={oversizedWriteAdmissionPolicy.Name}");
if (adaptiveInstrumentationEnabled)
{
    Console.WriteLine("QUIC_ADAPTIVE_RUNTIME_EPOCH_CONTRACT=adaptive-runtime-epoch-raw-v2");
    Console.WriteLine("QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_CONTRACT=adaptive-runtime-unified-epoch-raw-v1");
    Console.WriteLine("QUIC_ACTOR_SERVICE_EVIDENCE_CONTRACT=quic-actor-service-epoch-v1");
    Console.WriteLine("QUIC_BUFFER_COPY_EVIDENCE_CONTRACT=quic-buffer-copy-epoch-v2");
    Console.WriteLine("QUIC_BUFFER_COPY_OPERATION_EVIDENCE_CONTRACT=quic-buffer-copy-raw-v2");
    Console.WriteLine("QUIC_BUFFER_RELEASE_EVIDENCE_CONTRACT=quic-buffer-release-raw-v2");
}
if (applicationSendTurnPolicy.ForcedMode is not null)
{
    Console.WriteLine("QUIC_APPLICATION_SEND_TURN_POLICY_CONTRACT=adaptive-runtime-application-send-turn-provenance-v1");
}
if (sendTurnObservationMode != QuicApplicationSendTurnObservationMode.Disabled)
{
    Console.WriteLine("QUIC_APPLICATION_SEND_TURN_EVIDENCE_CONTRACT=adaptive-runtime-application-send-turn-raw-v1");
}
if (sendBatchObservationMode != QuicApplicationSendBatchObservationMode.Disabled)
{
    Console.WriteLine("QUIC_APPLICATION_SEND_BATCH_EVIDENCE_CONTRACT=adaptive-runtime-application-send-batch-raw-v1");
}
if (burstObservationMode != QuicQueuedSendBurstObservationMode.Disabled)
{
    Console.WriteLine("QUIC_QUEUED_SEND_BURST_EVIDENCE_CONTRACT=adaptive-runtime-queued-send-burst-raw-v1");
}
if (oversizedObservationMode != QuicOversizedWriteAdmissionObservationMode.Disabled)
{
    Console.WriteLine("QUIC_OVERSIZED_WRITE_ADMISSION_EVIDENCE_CONTRACT=adaptive-runtime-oversized-write-admission-raw-v1");
}
if (adaptiveInstrumentationEnabled)
{
    Console.WriteLine("QUIC_ADAPTIVE_RUNTIME_STAGE1_UNIFIED_CONTRACT=adaptive-runtime-stage1-unified-epoch-raw-v1");
}

try
{
    while (true)
    {
        QuicConnection connection;
        try
        {
            connection = await listener.AcceptConnectionAsync(default);
        }
        catch (QuicException ex)
        {
            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer ignored failed inbound establishment: {ex.Message}");
            }

            continue;
        }

        var connectionIndex = Interlocked.Increment(ref connectionCount);
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer accepted connection #{connectionIndex} for ALPN '{alpn}'");
        }

        _ = HandleConnectionAsync(connection, connectionIndex, default, debugLogging, summaryLogging, capacitySummaryLogging, echoResponses, downloadPayload, downloadWriteSizeBytes, boundedFinalEchoBytes);
    }
}
catch (OperationCanceledException)
{
}
catch (ObjectDisposedException)
{
}
catch (QuicException ex)
{
    if (debugLogging)
    {
        Console.Error.WriteLine($"IncursaRawQuicServer listener stopped with QUIC error: {ex.Message}");
    }
}
finally
{
    await listener.DisposeAsync();
}

static (string Name, QuicReceiveCreditPolicyMode? ForcedMode, bool ShadowEnabled) ResolveAdaptiveRuntimePolicy(string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" => ("unset", null, false),
        "legacy_current" => ("legacy_current", QuicReceiveCreditPolicyMode.LegacyCurrent, false),
        "immediate" => ("immediate", QuicReceiveCreditPolicyMode.Immediate, false),
        "read_dominant_batch" => ("read_dominant_batch", QuicReceiveCreditPolicyMode.ReadDominantBatch, false),
        "shadow" => ("shadow", QuicReceiveCreditPolicyMode.LegacyCurrent, true),
        _ => throw new InvalidOperationException(
            "PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY must be unset, legacy_current, immediate, read_dominant_batch, or shadow."),
    };
}

static (
    string Name,
    QuicApplicationSendTurnPolicyMode? ForcedMode,
    QuicApplicationSendTurnObservationMode ObservationMode) ResolveApplicationSendTurnPolicy(string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" => ("unset", null, QuicApplicationSendTurnObservationMode.Disabled),
        "legacy_current" => (
            "legacy_current",
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            QuicApplicationSendTurnObservationMode.Disabled),
        "conservative" => (
            "conservative",
            QuicApplicationSendTurnPolicyMode.Conservative,
            QuicApplicationSendTurnObservationMode.Disabled),
        "observe_only" => (
            "observe_only",
            null,
            QuicApplicationSendTurnObservationMode.ObserveOnly),
        "shadow" => (
            "shadow",
            null,
            QuicApplicationSendTurnObservationMode.Shadow),
        _ => throw new InvalidOperationException(
            "PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY must be unset, legacy_current, conservative, observe_only, or shadow."),
    };
}

static (
    string Name,
    QuicApplicationSendBatchPolicyMode? ForcedMode,
    QuicApplicationSendBatchObservationMode ObservationMode) ResolveApplicationSendBatchPolicy(
    string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" => ("unset", null, QuicApplicationSendBatchObservationMode.Disabled),
        "legacy_current" => (
            "legacy_current",
            QuicApplicationSendBatchPolicyMode.LegacyCurrent,
            QuicApplicationSendBatchObservationMode.Disabled),
        "single_eligible" => (
            "single_eligible",
            QuicApplicationSendBatchPolicyMode.SingleEligible,
            QuicApplicationSendBatchObservationMode.Disabled),
        "observe_only" => (
            "observe_only",
            null,
            QuicApplicationSendBatchObservationMode.ObserveOnly),
        "shadow" => (
            "shadow",
            null,
            QuicApplicationSendBatchObservationMode.Shadow),
        _ => throw new InvalidOperationException(
            "PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_BATCH_POLICY must be unset, legacy_current, single_eligible, observe_only, or shadow."),
    };
}

static (
    string Name,
    QuicQueuedSendBurstPolicyMode? ForcedMode,
    QuicQueuedSendBurstObservationMode ObservationMode) ResolveQueuedSendBurstPolicy(
    string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" => ("unset", null, QuicQueuedSendBurstObservationMode.Disabled),
        "legacy_current" => (
            "legacy_current",
            QuicQueuedSendBurstPolicyMode.LegacyCurrent,
            QuicQueuedSendBurstObservationMode.Disabled),
        "single_datagram" => (
            "single_datagram",
            QuicQueuedSendBurstPolicyMode.SingleDatagram,
            QuicQueuedSendBurstObservationMode.Disabled),
        "observe_only" => (
            "observe_only",
            null,
            QuicQueuedSendBurstObservationMode.ObserveOnly),
        "shadow" => (
            "shadow",
            null,
            QuicQueuedSendBurstObservationMode.Shadow),
        _ => throw new InvalidOperationException(
            "PROTOCOL_LAB_INCURSA_RAW_QUIC_QUEUED_SEND_BURST_POLICY must be unset, legacy_current, single_datagram, observe_only, or shadow."),
    };
}

static (
    string Name,
    QuicOversizedWriteAdmissionPolicyMode? ForcedMode,
    QuicOversizedWriteAdmissionObservationMode ObservationMode) ResolveOversizedWriteAdmissionPolicy(
    string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        null or "" => ("unset", null, QuicOversizedWriteAdmissionObservationMode.Disabled),
        "legacy_current" => (
            "legacy_current",
            QuicOversizedWriteAdmissionPolicyMode.LegacyCurrent,
            QuicOversizedWriteAdmissionObservationMode.Disabled),
        "single_fragment" => (
            "single_fragment",
            QuicOversizedWriteAdmissionPolicyMode.SingleFragment,
            QuicOversizedWriteAdmissionObservationMode.Disabled),
        "bounded_multi_fragment" => (
            "bounded_multi_fragment",
            QuicOversizedWriteAdmissionPolicyMode.BoundedMultiFragment,
            QuicOversizedWriteAdmissionObservationMode.Disabled),
        "observe_only" => (
            "observe_only",
            null,
            QuicOversizedWriteAdmissionObservationMode.ObserveOnly),
        "shadow" => (
            "shadow",
            null,
            QuicOversizedWriteAdmissionObservationMode.Shadow),
        _ => throw new InvalidOperationException(
            "PROTOCOL_LAB_INCURSA_RAW_QUIC_OVERSIZED_WRITE_ADMISSION_POLICY must be unset, legacy_current, single_fragment, bounded_multi_fragment, observe_only, or shadow."),
    };
}

static QuicApplicationSendTurnObservationMode EnableUnifiedSendTurnObservation(
    QuicApplicationSendTurnObservationMode mode)
    => mode == QuicApplicationSendTurnObservationMode.Disabled
        ? QuicApplicationSendTurnObservationMode.Shadow
        : mode;

static QuicApplicationSendBatchObservationMode EnableUnifiedSendBatchObservation(
    QuicApplicationSendBatchObservationMode mode)
    => mode == QuicApplicationSendBatchObservationMode.Disabled
        ? QuicApplicationSendBatchObservationMode.Shadow
        : mode;

static QuicQueuedSendBurstObservationMode EnableUnifiedBurstObservation(
    QuicQueuedSendBurstObservationMode mode)
    => mode == QuicQueuedSendBurstObservationMode.Disabled
        ? QuicQueuedSendBurstObservationMode.Shadow
        : mode;

static QuicOversizedWriteAdmissionObservationMode EnableUnifiedOversizedObservation(
    QuicOversizedWriteAdmissionObservationMode mode)
    => mode == QuicOversizedWriteAdmissionObservationMode.Disabled
        ? QuicOversizedWriteAdmissionObservationMode.Shadow
        : mode;

static async Task HandleConnectionAsync(QuicConnection connection, int connectionIndex, CancellationToken cancellationToken, bool debugLogging, bool summaryLogging, bool capacitySummaryLogging, bool echoResponses, byte[]? downloadPayload, int downloadWriteSizeBytes, int? boundedFinalEchoBytes)
{
    try
    {
        var streamIndex = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var stream = await connection.TryAcceptInboundStreamAsync(cancellationToken);
            if (stream is null)
            {
                break;
            }

            var acceptedStreamIndex = Interlocked.Increment(ref streamIndex);
            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer accepted inbound stream #{acceptedStreamIndex} on connection #{connectionIndex}");
            }

            _ = HandleStreamAsync(stream, connectionIndex, acceptedStreamIndex, cancellationToken, debugLogging, summaryLogging, echoResponses, downloadPayload, downloadWriteSizeBytes, boundedFinalEchoBytes);
        }
    }
    catch (OperationCanceledException)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} stopped: cancellation requested");
        }
    }
    catch (QuicException ex)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} stopped with QUIC error: {ex.Message}");
        }
    }
    catch (ObjectDisposedException ex)
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer connection #{connectionIndex} disposed: {ex.Message}");
        }
    }
    finally
    {
        if (capacitySummaryLogging)
        {
            QuicPeerStreamCapacityStateSnapshot snapshot =
                connection.Runtime.StreamRegistry.Bookkeeping.CapturePeerStreamCapacityStateSnapshot();
            Console.Error.WriteLine(
                $"IncursaRawQuicServer capacity-summary connection={connectionIndex} " +
                $"incomingBidiLimit={snapshot.IncomingBidirectionalLimit} incomingUniLimit={snapshot.IncomingUnidirectionalLimit} " +
                $"trackedBidi={snapshot.TrackedBidirectional} trackedUni={snapshot.TrackedUnidirectional} " +
                $"releasedBidi={snapshot.ReleaseReportedBidirectional} releasedUni={snapshot.ReleaseReportedUnidirectional} " +
                $"fullyClosedUnreleasedBidi={snapshot.FullyClosedUnreleasedBidirectional} " +
                $"fullyClosedUnreleasedUni={snapshot.FullyClosedUnreleasedUnidirectional} " +
                $"receiveOpenUnreleasedBidi={snapshot.ReceiveOpenUnreleasedBidirectional} " +
                $"receiveOpenUnreleasedUni={snapshot.ReceiveOpenUnreleasedUnidirectional} " +
                $"sendOpenUnreleasedBidi={snapshot.SendOpenUnreleasedBidirectional} " +
                $"sendOpenUnreleasedUni={snapshot.SendOpenUnreleasedUnidirectional}");
        }

        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer closing connection #{connectionIndex}");
        }

        await connection.DisposeAsync();
    }
}

static async Task HandleStreamAsync(QuicStream stream, int connectionIndex, int streamIndex, CancellationToken cancellationToken, bool debugLogging, bool summaryLogging, bool echoResponses, byte[]? downloadPayload, int downloadWriteSizeBytes, int? boundedFinalEchoBytes)
{
    var reachedEof = false;
    var completedWrites = false;
    long bytesReadTotal = 0;
    long bytesSentTotal = 0;
    var outcome = "completed";
    var error = string.Empty;

    try
    {
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer handling stream #{streamIndex} on connection #{connectionIndex}");
        }

        var buffer = ArrayPool<byte>.Shared.Rent(RawQuicEchoBufferBytes);
        try
        {
            if (downloadPayload is not null)
            {
                var requestLength = 0;
                while (requestLength <= DownloadRequestLength)
                {
                    var bytesRead = await stream.TryReadTerminalAsync(
                        buffer.AsMemory(requestLength, DownloadRequestLength + 1 - requestLength),
                        cancellationToken);
                    if (bytesRead <= 0)
                    {
                        reachedEof = true;
                        break;
                    }

                    requestLength += bytesRead;
                    bytesReadTotal += bytesRead;
                }

                if (!IsValidDownloadRequest(buffer.AsSpan(0, requestLength), downloadPayload.Length))
                {
                    throw new InvalidDataException($"Invalid raw QUIC download request length or payload size ({requestLength} bytes).");
                }

                for (var offset = 0; offset < downloadPayload.Length; offset += downloadWriteSizeBytes)
                {
                    var count = Math.Min(downloadWriteSizeBytes, downloadPayload.Length - offset);
                    await stream.WriteAsync(downloadPayload.AsMemory(offset, count), cancellationToken);
                    bytesSentTotal += count;
                }
            }
            else
            {
                if (boundedFinalEchoBytes is int expectedEchoBytes && stream.CanWrite)
                {
                    var received = 0;
                    while (received < expectedEchoBytes)
                    {
                        var bytesRead = await stream.TryReadTerminalAsync(
                            buffer.AsMemory(received, expectedEchoBytes - received),
                            cancellationToken);
                        if (bytesRead <= 0)
                        {
                            throw new InvalidDataException(
                                $"Raw QUIC request ended after {received} of {expectedEchoBytes} declared bytes.");
                        }

                        received += bytesRead;
                        bytesReadTotal += bytesRead;
                    }

                    var trailingBytes = await stream.TryReadTerminalAsync(buffer.AsMemory(0, 1), cancellationToken);
                    if (trailingBytes > 0)
                    {
                        throw new InvalidDataException(
                            $"Raw QUIC request exceeded its declared {expectedEchoBytes}-byte payload.");
                    }

                    reachedEof = true;
                    await stream.WriteFinalAsync(buffer.AsMemory(0, expectedEchoBytes), cancellationToken);
                    bytesSentTotal += expectedEchoBytes;
                    completedWrites = true;

                    if (debugLogging)
                    {
                        Console.Error.WriteLine(
                            $"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} " +
                            $"echoed and completed {expectedEchoBytes} declared byte(s)");
                    }
                }
                else
                {
                    while (true)
                    {
                        var bytesRead = await stream.TryReadTerminalAsync(buffer.AsMemory(0, RawQuicEchoBufferBytes), cancellationToken);
                        if (bytesRead <= 0)
                        {
                            reachedEof = true;
                            if (debugLogging)
                            {
                                Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} reached EOF after read loop");
                            }
                            break;
                        }

                        if (debugLogging)
                        {
                            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} read {bytesRead} byte(s)");
                        }

                        bytesReadTotal += bytesRead;
                        if (echoResponses && stream.CanWrite)
                        {
                            await stream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                            bytesSentTotal += bytesRead;

                            if (debugLogging)
                            {
                                Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} echoed {bytesRead} byte(s)");
                            }
                        }
                    }
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (stream.CanWrite && !completedWrites)
        {
            await stream.CompleteWritesAsync(cancellationToken);
            completedWrites = true;
            if (debugLogging)
            {
                Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} completed writes");
            }
        }
    }
    catch (OperationCanceledException)
    {
        outcome = "canceled";
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} canceled");
        }
    }
    catch (QuicException ex)
    {
        outcome = "quic-error";
        error = ex.Message;
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} failed with QUIC error: {ex.Message}");
        }
    }
    catch (Exception ex)
    {
        outcome = "error";
        error = ex.Message;
        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer stream #{streamIndex} on connection #{connectionIndex} failed: {ex}");
        }
    }
    finally
    {
        if (summaryLogging)
        {
            Console.Error.WriteLine(
                $"IncursaRawQuicServer stream-summary connection={connectionIndex} stream={streamIndex} " +
                $"readBytes={bytesReadTotal} sentBytes={bytesSentTotal} reachedEof={reachedEof} " +
                $"completedWrites={completedWrites} outcome={outcome} error=\"{error}\"");
        }

        if (debugLogging)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer closing stream #{streamIndex} on connection #{connectionIndex}");
        }

        // The connection runtime owns sent-packet recovery after the public facade completes.
        // Dispose promptly so completed streams no longer count as live runtime observers.
        await stream.DisposeAsync();
    }
}

static int? ResolveBoundedFinalEchoBytes(bool echoResponses, string? behavior, string? payloadSizeText)
{
    if (!echoResponses
        || behavior?.StartsWith("duplex-streams", StringComparison.OrdinalIgnoreCase) == true
        || !int.TryParse(payloadSizeText, out var payloadSize)
        || payloadSize is <= 0 or > SmallApplicationWriteSizeBytes)
    {
        return null;
    }

    return payloadSize;
}

static byte[] CreateDownloadPayload(string? payloadLengthText)
{
    if (!int.TryParse(payloadLengthText, out var payloadLength) ||
        payloadLength is <= 0 or > MaximumDownloadPayloadLength)
    {
        throw new InvalidOperationException(
            $"PROTOCOL_LAB_INCURSA_RAW_QUIC_PAYLOAD_SIZE_BYTES must be between 1 and {MaximumDownloadPayloadLength} for server-to-client workloads.");
    }

    var payload = GC.AllocateUninitializedArray<byte>(payloadLength);
    for (var index = 0; index < payload.Length; index++)
    {
        payload[index] = (byte)(index % 251);
    }

    return payload;
}

static int ResolveDownloadWriteSizeBytes(string? behavior, byte[]? downloadPayload)
{
    var expectedPayloadLength = behavior?.ToLowerInvariant() switch
    {
        SmallSustainedDownloadBehavior => SmallSustainedDownloadPayloadLength,
        FixedTotalSmallSustainedDownloadBehavior => FixedTotalSmallSustainedDownloadPayloadLength,
        _ => 0,
    };

    if (expectedPayloadLength == 0)
    {
        return RawQuicDownloadChunkBytes;
    }

    if (downloadPayload?.Length != expectedPayloadLength)
    {
        throw new InvalidOperationException(
            $"Behavior '{behavior}' requires server-to-client payload size {expectedPayloadLength} bytes.");
    }

    return SmallApplicationWriteSizeBytes;
}

static bool IsValidDownloadRequest(ReadOnlySpan<byte> request, int expectedPayloadLength)
{
    return request.Length == DownloadRequestLength &&
        request[..DownloadRequestMagic.Length].SequenceEqual("PLAB-DL1"u8) &&
        BinaryPrimitives.ReadUInt64BigEndian(request[DownloadRequestMagic.Length..]) == (ulong)expectedPayloadLength;
}

static X509Certificate2 GenerateSelfSignedCertificate(string subject)
{
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var request = new CertificateRequest(subject, ecdsa, HashAlgorithmName.SHA256);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
    var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    return X509CertificateLoader.LoadPkcs12(
        cert.Export(X509ContentType.Pfx),
        (string?)null,
        X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet);
}

static int GetFreePort()
{
    using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    return ((IPEndPoint)socket.LocalEndPoint!).Port;
}

internal sealed class AdaptiveRuntimeEpochPublisher
{
    private const string OutputPrefix = "QUIC_ADAPTIVE_RUNTIME_EPOCH_JSON=";
    private const string ApplicationSendTurnProvenanceOutputPrefix = "QUIC_APPLICATION_SEND_TURN_POLICY_JSON=";
    private const string ApplicationSendTurnEvidenceOutputPrefix = "QUIC_APPLICATION_SEND_TURN_EVIDENCE_JSON=";
    private const string ApplicationSendBatchEvidenceOutputPrefix = "QUIC_APPLICATION_SEND_BATCH_EVIDENCE_JSON=";
    private const string QueuedSendBurstEvidenceOutputPrefix = "QUIC_QUEUED_SEND_BURST_EVIDENCE_JSON=";
    private const string OversizedWriteAdmissionEvidenceOutputPrefix = "QUIC_OVERSIZED_WRITE_ADMISSION_EVIDENCE_JSON=";
    private const string Stage1UnifiedEpochOutputPrefix = "QUIC_ADAPTIVE_RUNTIME_STAGE1_UNIFIED_EPOCH_JSON=";
    private const string UnifiedEpochOutputPrefix = "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_JSON=";
    private const string UnifiedEpochFailureOutputPrefix = "QUIC_ADAPTIVE_RUNTIME_UNIFIED_EPOCH_FAILURE_JSON=";
    private const string BufferCopyOutputPrefix = "QUIC_BUFFER_COPY_OPERATION_EVIDENCE_JSON=";
    private const string BufferReleaseOutputPrefix = "QUIC_BUFFER_RELEASE_EVIDENCE_JSON=";
    private const string BufferEvidenceFailureOutputPrefix = "QUIC_BUFFER_EVIDENCE_FAILURE_JSON=";
    private readonly QuicAdaptiveRuntimeStage1PolicySnapshot? configuredStage1Policy;
    private readonly Channel<AdaptiveRuntimeEpochRecord> epochs = Channel.CreateBounded<AdaptiveRuntimeEpochRecord>(
        new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false,
        });
    private readonly Channel<ApplicationSendTurnPolicyProvenanceRecord> applicationSendTurnProvenance = Channel.CreateBounded<ApplicationSendTurnPolicyProvenanceRecord>(
        new BoundedChannelOptions(4096)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations = false,
        });
    private readonly Channel<ApplicationSendTurnEvidenceRecord> applicationSendTurnEvidence =
        Channel.CreateBounded<ApplicationSendTurnEvidenceRecord>(
            new BoundedChannelOptions(4096)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });
    private readonly Channel<ApplicationSendBatchEvidenceRecord> applicationSendBatchEvidence =
        CreateEvidenceChannel<ApplicationSendBatchEvidenceRecord>();
    private readonly Channel<QueuedSendBurstEvidenceRecord> queuedSendBurstEvidence =
        CreateEvidenceChannel<QueuedSendBurstEvidenceRecord>();
    private readonly Channel<OversizedWriteAdmissionEvidenceRecord> oversizedWriteAdmissionEvidence =
        CreateEvidenceChannel<OversizedWriteAdmissionEvidenceRecord>();
    private readonly Channel<Stage1UnifiedEpochRecord> stage1UnifiedEpochs =
        CreateEvidenceChannel<Stage1UnifiedEpochRecord>();
    private readonly Channel<UnifiedAdaptiveRuntimeEpochRecord> unifiedEpochs =
        CreateEvidenceChannel<UnifiedAdaptiveRuntimeEpochRecord>();
    private readonly Channel<BufferCopyEvidenceRecord> bufferCopies =
        CreateEvidenceChannel<BufferCopyEvidenceRecord>();
    private readonly Channel<BufferReleaseEvidenceRecord> bufferReleases =
        CreateEvidenceChannel<BufferReleaseEvidenceRecord>();
    private long nextConnectionKey;

    internal AdaptiveRuntimeEpochPublisher(
        QuicAdaptiveRuntimeStage1PolicySnapshot? configuredStage1Policy)
    {
        this.configuredStage1Policy = configuredStage1Policy;
        _ = WriteEpochsAsync();
        _ = WriteApplicationSendTurnProvenanceAsync();
        _ = WriteApplicationSendTurnEvidenceAsync();
        _ = WriteApplicationSendBatchEvidenceAsync();
        _ = WriteQueuedSendBurstEvidenceAsync();
        _ = WriteOversizedWriteAdmissionEvidenceAsync();
        _ = WriteStage1UnifiedEpochsAsync();
        _ = WriteUnifiedEpochsAsync();
        _ = WriteBufferCopiesAsync();
        _ = WriteBufferReleasesAsync();
    }

    internal ConnectionSinks CreateConnectionSinks()
    {
        ConnectionSink sink = new(
            this,
            $"connection-{Interlocked.Increment(ref nextConnectionKey):D4}",
            configuredStage1Policy
                ?? throw new InvalidOperationException(
                    "Unified adaptive-runtime evidence requires a configured Stage 1 policy snapshot."));
        return sink.CreateSinks();
    }

    private static Channel<T> CreateEvidenceChannel<T>()
        => Channel.CreateBounded<T>(
            new BoundedChannelOptions(4096)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });

    private async Task WriteEpochsAsync()
    {
        try
        {
            await foreach (AdaptiveRuntimeEpochRecord epoch in epochs.Reader.ReadAllAsync())
            {
                Console.WriteLine(OutputPrefix + JsonSerializer.Serialize(epoch, AdaptiveRuntimeEpochJsonContext.Default.AdaptiveRuntimeEpochRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer adaptive-runtime epoch writer stopped: {ex.Message}");
        }
    }

    private async Task WriteApplicationSendTurnProvenanceAsync()
    {
        try
        {
            await foreach (ApplicationSendTurnPolicyProvenanceRecord provenance in applicationSendTurnProvenance.Reader.ReadAllAsync())
            {
                Console.WriteLine(ApplicationSendTurnProvenanceOutputPrefix + JsonSerializer.Serialize(
                    provenance,
                    AdaptiveRuntimeEpochJsonContext.Default.ApplicationSendTurnPolicyProvenanceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer application-send turn provenance writer stopped: {ex.Message}");
        }
    }

    private async Task WriteApplicationSendTurnEvidenceAsync()
    {
        try
        {
            await foreach (ApplicationSendTurnEvidenceRecord evidence in applicationSendTurnEvidence.Reader.ReadAllAsync())
            {
                Console.WriteLine(ApplicationSendTurnEvidenceOutputPrefix + JsonSerializer.Serialize(
                    evidence,
                    AdaptiveRuntimeEpochJsonContext.Default.ApplicationSendTurnEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer application-send turn evidence writer stopped: {ex.Message}");
        }
    }

    private async Task WriteApplicationSendBatchEvidenceAsync()
    {
        try
        {
            await foreach (ApplicationSendBatchEvidenceRecord evidence in applicationSendBatchEvidence.Reader.ReadAllAsync())
            {
                Console.WriteLine(ApplicationSendBatchEvidenceOutputPrefix + JsonSerializer.Serialize(
                    evidence,
                    AdaptiveRuntimeEpochJsonContext.Default.ApplicationSendBatchEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer application-send batch evidence writer stopped: {ex.Message}");
        }
    }

    private async Task WriteQueuedSendBurstEvidenceAsync()
    {
        try
        {
            await foreach (QueuedSendBurstEvidenceRecord evidence in queuedSendBurstEvidence.Reader.ReadAllAsync())
            {
                Console.WriteLine(QueuedSendBurstEvidenceOutputPrefix + JsonSerializer.Serialize(
                    evidence,
                    AdaptiveRuntimeEpochJsonContext.Default.QueuedSendBurstEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer queued-send burst evidence writer stopped: {ex.Message}");
        }
    }

    private async Task WriteOversizedWriteAdmissionEvidenceAsync()
    {
        try
        {
            await foreach (OversizedWriteAdmissionEvidenceRecord evidence in oversizedWriteAdmissionEvidence.Reader.ReadAllAsync())
            {
                Console.WriteLine(OversizedWriteAdmissionEvidenceOutputPrefix + JsonSerializer.Serialize(
                    evidence,
                    AdaptiveRuntimeEpochJsonContext.Default.OversizedWriteAdmissionEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer oversized-write admission evidence writer stopped: {ex.Message}");
        }
    }

    private async Task WriteStage1UnifiedEpochsAsync()
    {
        try
        {
            await foreach (Stage1UnifiedEpochRecord epoch in stage1UnifiedEpochs.Reader.ReadAllAsync())
            {
                Console.WriteLine(Stage1UnifiedEpochOutputPrefix + JsonSerializer.Serialize(
                    epoch,
                    AdaptiveRuntimeEpochJsonContext.Default.Stage1UnifiedEpochRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer Stage 1 unified epoch writer stopped: {ex.Message}");
        }
    }

    private async Task WriteUnifiedEpochsAsync()
    {
        try
        {
            await foreach (UnifiedAdaptiveRuntimeEpochRecord epoch in unifiedEpochs.Reader.ReadAllAsync())
            {
                Console.WriteLine(UnifiedEpochOutputPrefix + JsonSerializer.Serialize(
                    epoch,
                    AdaptiveRuntimeEpochJsonContext.Default.UnifiedAdaptiveRuntimeEpochRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer unified adaptive-runtime epoch writer stopped: {ex.Message}");
        }
    }

    private async Task WriteBufferReleasesAsync()
    {
        try
        {
            await foreach (BufferReleaseEvidenceRecord release in bufferReleases.Reader.ReadAllAsync())
            {
                Console.WriteLine(BufferReleaseOutputPrefix + JsonSerializer.Serialize(
                    release,
                    AdaptiveRuntimeEpochJsonContext.Default.BufferReleaseEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer buffer-release evidence writer stopped: {ex.Message}");
        }
    }

    private async Task WriteBufferCopiesAsync()
    {
        try
        {
            await foreach (BufferCopyEvidenceRecord copy in bufferCopies.Reader.ReadAllAsync())
            {
                Console.WriteLine(BufferCopyOutputPrefix + JsonSerializer.Serialize(
                    copy,
                    AdaptiveRuntimeEpochJsonContext.Default.BufferCopyEvidenceRecord));
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"IncursaRawQuicServer buffer-copy evidence writer stopped: {ex.Message}");
        }
    }

    private sealed class ConnectionSink :
        IQuicApplicationSendTurnPolicyProvenanceSink,
        IQuicApplicationSendTurnEvidenceSink,
        IQuicApplicationSendBatchEvidenceSink,
        IQuicQueuedSendBurstEvidenceSink,
        IQuicOversizedWriteAdmissionEvidenceSink,
        IQuicActorServiceEvidenceSink,
        IQuicBufferCopyEvidenceSink,
        IQuicBufferReleaseEvidenceSink,
        IQuicAdaptiveRuntimeUnifiedEpochEvidenceSink
    {
        private readonly AdaptiveRuntimeEpochPublisher owner;
        private readonly string connectionKey;
        private readonly QuicAdaptiveRuntimeUnifiedEpochEvidenceAccumulator
            unifiedAccumulator;

        internal ConnectionSink(
            AdaptiveRuntimeEpochPublisher owner,
            string connectionKey,
            QuicAdaptiveRuntimeStage1PolicySnapshot configuredStage1Policy)
        {
            this.owner = owner;
            this.connectionKey = connectionKey;
            unifiedAccumulator = new(
                in configuredStage1Policy,
                this);
        }

        internal ConnectionSinks CreateSinks()
            => new(
                unifiedAccumulator,
                this,
                this,
                this,
                this,
                this,
                this,
                this);

        public bool TryPublish(
            in QuicAdaptiveRuntimeUnifiedEpochEvidence evidence)
        {
            bool rawPublished = owner.epochs.Writer.TryWrite(
                new AdaptiveRuntimeEpochRecord(
                "adaptive-runtime-epoch-raw-v2",
                connectionKey,
                evidence.ConnectionObservation,
                evidence.ReceiveCreditSnapshot,
                evidence.PostServiceBoundary));
            bool stage1Published = owner.stage1UnifiedEpochs.Writer.TryWrite(
                new Stage1UnifiedEpochRecord(
                    "adaptive-runtime-stage1-unified-epoch-raw-v1",
                    connectionKey,
                    evidence.Stage1));
            bool unifiedPublished = owner.unifiedEpochs.Writer.TryWrite(
                new UnifiedAdaptiveRuntimeEpochRecord(
                    "adaptive-runtime-unified-epoch-raw-v1",
                    connectionKey,
                    evidence));
            if (!rawPublished || !stage1Published || !unifiedPublished)
            {
                owner.TryReportUnifiedEpochExportFailure(
                    connectionKey,
                    evidence.ConnectionEpochSequence,
                    rawPublished,
                    stage1Published,
                    unifiedPublished);
            }

            return rawPublished && stage1Published && unifiedPublished;
        }

        public bool TryPublish(in QuicApplicationSendTurnPolicyProvenance provenance)
            => owner.applicationSendTurnProvenance.Writer.TryWrite(new ApplicationSendTurnPolicyProvenanceRecord(
                provenance.SchemaVersion,
                connectionKey,
                provenance.AxisId,
                provenance.RuleVersion,
                provenance.AppliedPolicy));

        public bool TryPublish(in QuicApplicationSendTurnEvidence evidence)
        {
            bool accumulated = unifiedAccumulator.TryPublish(in evidence);
            return owner.applicationSendTurnEvidence.Writer.TryWrite(new ApplicationSendTurnEvidenceRecord(
                "adaptive-runtime-application-send-turn-raw-v1",
                connectionKey,
                evidence.Mode,
                evidence.Observation,
                evidence.HasRecommendation,
                evidence.HasRecommendation ? evidence.Snapshot : null)) && accumulated;
        }

        public bool TryPublish(in QuicApplicationSendBatchEvidence evidence)
        {
            bool accumulated = unifiedAccumulator.TryPublish(in evidence);
            return owner.applicationSendBatchEvidence.Writer.TryWrite(
                new ApplicationSendBatchEvidenceRecord(
                    "adaptive-runtime-application-send-batch-raw-v1",
                    connectionKey,
                    evidence)) && accumulated;
        }

        public bool TryPublish(in QuicQueuedSendBurstEvidence evidence)
        {
            bool accumulated = unifiedAccumulator.TryPublish(in evidence);
            return owner.queuedSendBurstEvidence.Writer.TryWrite(
                new QueuedSendBurstEvidenceRecord(
                    "adaptive-runtime-queued-send-burst-raw-v1",
                    connectionKey,
                    evidence)) && accumulated;
        }

        public bool TryPublish(in QuicOversizedWriteAdmissionEvidence evidence)
        {
            bool accumulated = unifiedAccumulator.TryPublish(in evidence);
            return owner.oversizedWriteAdmissionEvidence.Writer.TryWrite(
                new OversizedWriteAdmissionEvidenceRecord(
                    "adaptive-runtime-oversized-write-admission-raw-v1",
                    connectionKey,
                    evidence)) && accumulated;
        }

        public bool TryPublish(in QuicActorServiceObservation observation)
            => unifiedAccumulator.TryPublish(in observation);

        public bool TryPublish(in QuicBufferCopyObservation observation)
        {
            bool accumulated =
                unifiedAccumulator.TryPublish(in observation);
            bool terminalReleaseTracked =
                (observation.Validity
                    & QuicBufferCopyValidity
                        .MissingTerminalReleaseCorrelation)
                == 0;
            bool rawPublished =
                !terminalReleaseTracked
                || owner.bufferCopies.Writer.TryWrite(
                    new BufferCopyEvidenceRecord(
                        "quic-buffer-copy-raw-v2",
                        connectionKey,
                        observation));
            if (!rawPublished)
            {
                owner.TryReportBufferEvidenceExportFailure(
                    connectionKey,
                    "copy",
                    observation.OperationSequence,
                    releaseSequence: null);
            }

            return accumulated && rawPublished;
        }

        public bool TryPublish(in QuicBufferReleaseObservation observation)
        {
            bool published = owner.bufferReleases.Writer.TryWrite(
                new BufferReleaseEvidenceRecord(
                    "quic-buffer-release-raw-v2",
                    connectionKey,
                    observation));
            if (!published)
            {
                owner.TryReportBufferEvidenceExportFailure(
                    connectionKey,
                    "release",
                    observation.OperationSequence,
                    observation.ReleaseSequence);
            }

            return published;
        }
    }

    private void TryReportUnifiedEpochExportFailure(
        string connectionKey,
        ulong connectionEpochSequence,
        bool rawEpochPublished,
        bool stage1EpochPublished,
        bool unifiedEpochPublished)
    {
        try
        {
            UnifiedAdaptiveRuntimeEpochExportFailureRecord failure = new(
                "adaptive-runtime-unified-epoch-export-failure-v1",
                connectionKey,
                connectionEpochSequence,
                rawEpochPublished,
                stage1EpochPublished,
                unifiedEpochPublished);
            Console.Error.WriteLine(
                UnifiedEpochFailureOutputPrefix
                + JsonSerializer.Serialize(
                    failure,
                    AdaptiveRuntimeEpochJsonContext.Default
                        .UnifiedAdaptiveRuntimeEpochExportFailureRecord));
        }
        catch (Exception)
        {
            // Evidence reporting remains behavior-neutral even when the
            // fallback diagnostic stream is unavailable.
        }
    }

    private void TryReportBufferEvidenceExportFailure(
        string connectionKey,
        string evidenceKind,
        ulong operationSequence,
        ulong? releaseSequence)
    {
        try
        {
            BufferEvidenceExportFailureRecord failure = new(
                "quic-buffer-evidence-export-failure-v1",
                connectionKey,
                evidenceKind,
                operationSequence,
                releaseSequence);
            Console.Error.WriteLine(
                BufferEvidenceFailureOutputPrefix
                + JsonSerializer.Serialize(
                    failure,
                    AdaptiveRuntimeEpochJsonContext.Default
                        .BufferEvidenceExportFailureRecord));
        }
        catch (Exception)
        {
            // Evidence reporting remains behavior-neutral even when the
            // fallback diagnostic stream is unavailable.
        }
    }

    internal readonly record struct ConnectionSinks(
        IQuicAdaptiveRuntimeShadowEpochSink EpochSink,
        IQuicApplicationSendTurnPolicyProvenanceSink ApplicationSendTurnPolicySink,
        IQuicApplicationSendTurnEvidenceSink ApplicationSendTurnEvidenceSink,
        IQuicApplicationSendBatchEvidenceSink ApplicationSendBatchEvidenceSink,
        IQuicQueuedSendBurstEvidenceSink QueuedSendBurstEvidenceSink,
        IQuicOversizedWriteAdmissionEvidenceSink OversizedWriteAdmissionEvidenceSink,
        IQuicActorServiceEvidenceSink ActorServiceEvidenceSink,
        IQuicBufferCopyEvidenceSink BufferCopyEvidenceSink);
}

internal readonly record struct AdaptiveRuntimeEpochRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicAdaptiveRuntimeConnectionObservation Observation,
    QuicReceiveCreditPolicySnapshot Snapshot,
    QuicAdaptiveRuntimePostServiceBoundary PostServiceBoundary);

internal readonly record struct ApplicationSendTurnPolicyProvenanceRecord(
    string SchemaVersion,
    string ConnectionKey,
    string AxisId,
    string RuleVersion,
    QuicApplicationSendTurnPolicyMode AppliedPolicy);

internal readonly record struct ApplicationSendTurnEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicApplicationSendTurnObservationMode Mode,
    QuicApplicationSendTurnObservation Observation,
    bool HasRecommendation,
    QuicApplicationSendTurnPolicySnapshot? Snapshot);

internal readonly record struct ApplicationSendBatchEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicApplicationSendBatchEvidence Evidence);

internal readonly record struct QueuedSendBurstEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicQueuedSendBurstEvidence Evidence);

internal readonly record struct OversizedWriteAdmissionEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicOversizedWriteAdmissionEvidence Evidence);

internal readonly record struct Stage1UnifiedEpochRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicAdaptiveRuntimeStage1EpochEvidence Epoch);

internal readonly record struct UnifiedAdaptiveRuntimeEpochRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicAdaptiveRuntimeUnifiedEpochEvidence Epoch);

internal readonly record struct UnifiedAdaptiveRuntimeEpochExportFailureRecord(
    string SchemaVersion,
    string ConnectionKey,
    ulong ConnectionEpochSequence,
    bool RawEpochPublished,
    bool Stage1EpochPublished,
    bool UnifiedEpochPublished);

internal readonly record struct BufferReleaseEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicBufferReleaseObservation Observation);

internal readonly record struct BufferCopyEvidenceRecord(
    string SchemaVersion,
    string ConnectionKey,
    QuicBufferCopyObservation Observation);

internal readonly record struct BufferEvidenceExportFailureRecord(
    string SchemaVersion,
    string ConnectionKey,
    string EvidenceKind,
    ulong OperationSequence,
    ulong? ReleaseSequence);

[System.Text.Json.Serialization.JsonSerializable(typeof(AdaptiveRuntimeEpochRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ApplicationSendTurnPolicyProvenanceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ApplicationSendTurnEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(ApplicationSendBatchEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(QueuedSendBurstEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(OversizedWriteAdmissionEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(Stage1UnifiedEpochRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(UnifiedAdaptiveRuntimeEpochRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(UnifiedAdaptiveRuntimeEpochExportFailureRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(BufferCopyEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(BufferReleaseEvidenceRecord))]
[System.Text.Json.Serialization.JsonSerializable(typeof(BufferEvidenceExportFailureRecord))]
[System.Text.Json.Serialization.JsonSourceGenerationOptions(
    PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true)]
internal sealed partial class AdaptiveRuntimeEpochJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
