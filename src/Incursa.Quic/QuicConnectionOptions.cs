// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;

namespace Incursa.Quic;

/// <summary>
/// Shared connection settings used by the consumer-facing QUIC facade.
/// </summary>
public abstract class QuicConnectionOptions
{
    // CONTEXT: These defaults are conservative baseline values that bound initial memory and queue
    // growth before the application overrides them.
    // SEE: QuicReceiveWindowSizes
    private const int DefaultConnectionReceiveWindow = 16 * 1024 * 1024;
    private const int DefaultStreamReceiveWindow = 64 * 1024;
    private const int DefaultMaxInboundDatagramQueueSize = 1024;
    private static readonly TimeSpan DefaultHandshakeTimeout = TimeSpan.FromSeconds(10);

    private QuicReceiveWindowSizes initialReceiveWindowSizes = new();
    private int maxDatagramFrameSize;
    private int maxInboundDatagramQueueSize;

    /// <summary>
    /// Prevents external derivation outside of the assembly.
    /// </summary>
    internal QuicConnectionOptions()
    {
        DefaultCloseErrorCode = -1;
        DefaultStreamErrorCode = -1;
        HandshakeTimeout = DefaultHandshakeTimeout;
        IdleTimeout = TimeSpan.Zero;
        KeepAliveInterval = Timeout.InfiniteTimeSpan;
        maxDatagramFrameSize = 0;
        maxInboundDatagramQueueSize = DefaultMaxInboundDatagramQueueSize;
        MaxInboundBidirectionalStreams = 0;
        MaxInboundUnidirectionalStreams = 0;
        initialReceiveWindowSizes = new QuicReceiveWindowSizes
        {
            Connection = DefaultConnectionReceiveWindow,
            LocallyInitiatedBidirectionalStream = DefaultStreamReceiveWindow,
            RemotelyInitiatedBidirectionalStream = DefaultStreamReceiveWindow,
            UnidirectionalStream = DefaultStreamReceiveWindow,
        };
    }

    /// <summary>
    /// Gets or sets the application error code used by the connection on dispose when no explicit close was sent.
    /// </summary>
    /// <remarks>
    /// The value is carried as QUIC application close metadata and is interpreted by the application protocol using the connection.
    /// </remarks>
    public long DefaultCloseErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the application error code used by streams on dispose when no explicit stream abort was sent.
    /// </summary>
    /// <remarks>
    /// The value is carried as application stream error metadata. It is not a QUIC transport error code.
    /// </remarks>
    public long DefaultStreamErrorCode { get; set; }

    /// <summary>
    /// Gets or sets the handshake timeout.
    /// </summary>
    public TimeSpan HandshakeTimeout { get; set; }

    /// <summary>
    /// Gets or sets the idle timeout.
    /// </summary>
    /// <remarks>
    /// Idle timeout and keep-alive control liveness of the current connection. They do not enable TLS session
    /// resumption or 0-RTT application data.
    /// </remarks>
    public TimeSpan IdleTimeout { get; set; }

    /// <summary>
    /// Gets or sets the receive-window sizes used when the connection is created.
    /// </summary>
    public QuicReceiveWindowSizes InitialReceiveWindowSizes
    {
        get => initialReceiveWindowSizes;
        set => initialReceiveWindowSizes = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    /// Gets or sets the callback invoked when the supported peer stream-capacity delta becomes available.
    /// </summary>
    /// <remarks>
    /// Applications that map many logical operations onto QUIC streams should use this callback as a backpressure
    /// signal instead of assuming another outbound stream can always be opened immediately.
    /// </remarks>
    public Action<QuicConnection, QuicStreamCapacityChangedArgs>? StreamCapacityCallback { get; set; }

    /// <summary>
    /// Gets or sets the complete DATAGRAM frame size this endpoint advertises for receiving DATAGRAM frames.
    /// </summary>
    /// <remarks>
    /// A value of 0 disables local DATAGRAM receive support and omits the max_datagram_frame_size transport parameter.
    /// </remarks>
    public int MaxDatagramFrameSize
    {
        get => maxDatagramFrameSize;
        set
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            maxDatagramFrameSize = value;
        }
    }

    /// <summary>
    /// Gets or sets the maximum number of received DATAGRAM payloads buffered for application receive.
    /// </summary>
    public int MaxInboundDatagramQueueSize
    {
        get => maxInboundDatagramQueueSize;
        set
        {
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value));
            }

            maxInboundDatagramQueueSize = value;
        }
    }

    /// <summary>
    /// Gets or sets the keep-alive interval.
    /// </summary>
    /// <remarks>
    /// Keep-alive traffic is only a liveness aid for an established connection. It is separate from session
    /// resumption and does not make replay-sensitive 0-RTT application data safe.
    /// </remarks>
    public TimeSpan KeepAliveInterval { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of inbound bidirectional streams.
    /// </summary>
    public int MaxInboundBidirectionalStreams { get; set; }

    /// <summary>
    /// Gets or sets the maximum number of inbound unidirectional streams.
    /// </summary>
    public int MaxInboundUnidirectionalStreams { get; set; }

    // CONTEXT: These internal-only controls let evidence hosts select one receive-credit
    // treatment before connection admission without expanding the supported public API.
    // SEE: QuicConnectionRuntime.ConfigureAdaptiveRuntimePolicy
    internal QuicReceiveCreditPolicyMode? ForcedReceiveCreditPolicyMode { get; set; }

    // CONTEXT: Internal-only campaign control. The default remains the null
    // planner fast path; a forced conservative mode is an explicit current
    // planner and does not grant a policy authority over runtime guards.
    internal QuicApplicationSendTurnPolicyMode? ForcedApplicationSendTurnPolicyMode { get; set; }

    internal bool AdaptiveRuntimeShadowEnabled { get; set; }

    internal TimeSpan AdaptiveRuntimeShadowEpochInterval { get; set; }

    internal IQuicAdaptiveRuntimeShadowEpochSink? AdaptiveRuntimeShadowEpochSink { get; set; }

    internal IQuicApplicationSendTurnPolicyProvenanceSink? ApplicationSendTurnPolicyProvenanceSink { get; set; }

    internal QuicApplicationSendTurnObservationMode ApplicationSendTurnObservationMode { get; set; }

    internal IQuicApplicationSendTurnEvidenceSink? ApplicationSendTurnEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 1 packet-plan control. This policy may
    // shorten only the already-legal application-send batch prefix.
    internal QuicApplicationSendBatchPolicyMode? ForcedApplicationSendBatchPolicyMode { get; set; }

    internal QuicApplicationSendBatchObservationMode ApplicationSendBatchObservationMode { get; set; }

    internal IQuicApplicationSendBatchEvidenceSink? ApplicationSendBatchEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 1 actor-turn cap. This policy may lower
    // only the datagram budget already authorized by transport guards.
    internal QuicQueuedSendBurstPolicyMode? ForcedQueuedSendBurstPolicyMode { get; set; }

    internal QuicQueuedSendBurstObservationMode QueuedSendBurstObservationMode { get; set; }

    internal IQuicQueuedSendBurstEvidenceSink? QueuedSendBurstEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 1 logical-write admission control. The
    // selected quantum is latched through fragmentation and completion.
    internal QuicOversizedWriteAdmissionPolicyMode? ForcedOversizedWriteAdmissionPolicyMode { get; set; }

    internal QuicOversizedWriteAdmissionObservationMode OversizedWriteAdmissionObservationMode { get; set; }

    internal IQuicOversizedWriteAdmissionEvidenceSink? OversizedWriteAdmissionEvidenceSink { get; set; }

    // CONTEXT: Stage 2 starts with behavior-neutral actor service
    // instrumentation. This does not install an actor work-quantum policy.
    internal QuicActorServiceObservationMode ActorServiceObservationMode { get; set; }

    internal IQuicActorServiceEvidenceSink? ActorServiceEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 2 buffer construction control. The
    // conservative value may only shorten an already legal combined prefix.
    internal QuicBufferCopyPolicyValue? ForcedBufferCopyPolicyValue { get; set; }

    // CONTEXT: Buffer-copy evidence may observe or shadow the conservative
    // coalescing cap without changing the default construction path.
    internal QuicBufferCopyObservationMode BufferCopyObservationMode { get; set; }

    internal IQuicBufferCopyEvidenceSink? BufferCopyEvidenceSink { get; set; }

    // CONTEXT: This fixed token is produced only by the reviewed, immutable
    // correctness-manifest path. It cannot authorize active or performance
    // behavior and is not exposed through public connection configuration.
    internal QuicAdaptiveRuntimeCorrectnessInteractionAuthorization?
        SendCompositionCorrectnessAuthorization { get; set; }

    // CONTEXT: This token authorizes only the exact reviewed A0-A7
    // send-admission correctness matrix. It remains internal, correctness
    // only, and cannot authorize adaptive selection or performance.
    internal QuicAdaptiveRuntimeAdmissionCorrectnessAuthorization?
        SendAdmissionCorrectnessAuthorization { get; set; }

    // CONTEXT: This token authorizes only the exact reviewed offline
    // send-admission A0-A7 measurement campaign. It remains internal,
    // offline-only, and cannot authorize active behavior or performance
    // acceptance.
    internal QuicAdaptiveRuntimeAdmissionPerformanceAuthorization?
        SendAdmissionPerformanceAuthorization { get; set; }

    // CONTEXT: This fixed token is produced only by the reviewed offline
    // send-composition campaign. It is not public configuration, cannot
    // authorize active behavior, and cannot authorize performance acceptance.
    internal QuicAdaptiveRuntimePerformanceInteractionAuthorization?
        SendCompositionPerformanceAuthorization { get; set; }

    // CONTEXT: Internal-only Stage 2 application-admission control. The
    // conservative value may add one bounded dispatcher-turn wait but cannot
    // reject work, raise a hard bound, or wait for network progress.
    internal QuicAdaptiveBackpressurePolicyValue?
        ForcedAdaptiveBackpressurePolicyValue { get; set; }

    internal QuicAdaptiveBackpressureObservationMode
        AdaptiveBackpressureObservationMode { get; set; }

    internal IQuicAdaptiveBackpressureEvidenceSink?
        AdaptiveBackpressureEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 3 packet-flush control. prompt may only
    // remove the existing optional small-write coalescing delay; it cannot
    // bypass recovery, pacing, congestion, amplification, or lifecycle guards.
    internal QuicPacketFlushCadencePolicyValue?
        ForcedPacketFlushCadencePolicyValue { get; set; }

    internal QuicPacketFlushCadenceObservationMode
        PacketFlushCadenceObservationMode { get; set; }

    internal IQuicPacketFlushCadenceEvidenceSink?
        PacketFlushCadenceEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 3 receive-delivery control. The
    // conservative value may return bytes from at most one existing receive
    // segment per productive application read without changing receive credit
    // selection, ordering, ownership, or terminal behavior.
    internal QuicReceiveDeliveryQuantumPolicyValue?
        ForcedReceiveDeliveryQuantumPolicyValue { get; set; }

    internal QuicReceiveDeliveryQuantumObservationMode
        ReceiveDeliveryQuantumObservationMode { get; set; }

    internal IQuicReceiveDeliveryQuantumEvidenceSink?
        ReceiveDeliveryQuantumEvidenceSink { get; set; }

    // CONTEXT: Placement is latched by the endpoint before server connection
    // options are returned. The per-connection sink is attached afterward and
    // receives that immutable decision without changing shard ownership.
    internal IQuicConnectionShardPlacementEvidenceSink?
        ConnectionShardPlacementEvidenceSink { get; set; }

    internal QuicConnectionShardPlacementObservationMode
        ConnectionShardPlacementObservationMode { get; set; }

    internal QuicConnectionShardPlacementPolicyValue?
        ForcedConnectionShardPlacementPolicyValue { get; set; }

    internal QuicApplicationDatagramBatchTransportObservationMode
        ApplicationDatagramBatchTransportObservationMode { get; set; }

    internal QuicApplicationDatagramBatchTransportPolicyValue?
        ForcedApplicationDatagramBatchTransportPolicyValue { get; set; }

    internal IQuicApplicationDatagramBatchTransportEvidenceSink?
        ApplicationDatagramBatchTransportEvidenceSink { get; set; }

    // CONTEXT: Internal-only Stage 5 connection-start selection. This wraps
    // only the already-implemented NewReno and CUBIC controllers. The applied
    // profile is immutable and cannot bypass recovery or pacing authority.
    internal QuicCongestionPacingProfileObservationMode
        CongestionPacingProfileObservationMode { get; set; }

    internal QuicCongestionPacingProfilePolicyValue?
        ForcedCongestionPacingProfilePolicyValue { get; set; }

    internal IQuicCongestionPacingProfileEvidenceSink?
        CongestionPacingProfileEvidenceSink { get; set; }
}
