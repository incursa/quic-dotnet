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
}
