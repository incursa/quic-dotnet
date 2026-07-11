// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks.Sources;

namespace Incursa.Quic;

/// <summary>
/// Owns the connection runtime shell, its single-consumer inbox, and the connection-owned transition path.
/// </summary>
// Partial layout:
// - QuicConnectionRuntime.cs keeps the shell, construction, and public entry points.
// - QuicConnectionRuntime.Protocol.cs owns TLS/bootstrap and protocol ingress.
// - QuicConnectionRuntime.Streams.cs owns stream-facing actions and flow-control publication.
// - QuicConnectionRuntime.Routing.cs owns packet/timer dispatch and connection-id event handling.
// - QuicConnectionRuntime.Paths.cs owns path validation, migration, promotion, and PMTU state.
// - QuicConnectionLifecycleTimerState owns lifecycle timer deadlines and terminal deadline bookkeeping.
// - QuicConnectionDiagnosticsState owns diagnostics sink resolution and enabled-state caching.
// - QuicConnectionIssuedConnectionIdState owns locally issued connection-ID bookkeeping and stateless-reset token tracking.
// - QuicConnectionRuntime.Lifecycle.cs owns terminal transitions, diagnostics, and shared helpers.

internal sealed partial class QuicConnectionRuntime : IAsyncDisposable, IDisposable
{
    private const ulong TerminalLifetimePtoMultiplier = 3;
    private const ulong MicrosecondsPerSecond = 1_000_000UL;
    private const int DefaultCloseFrameOverheadBytes = 32;
    private const int PreferredAddressIPv4BytesLength = sizeof(uint);
    private const int PreferredAddressIPv6BytesLength = 16;
    // CONTEXT: preferred-address CID sequence slot
    // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Protocol.cs#TryRegisterPreferredAddressConnectionId
    // SEE: code:src/Incursa.Quic/QuicConnectionPeerConnectionIdState.cs#TryAcceptPreferredAddressConnectionId
    // Sequence 1 is reserved for the preferred-address CID path so the runtime
    // can validate the same transport-parameter slot consistently across
    // retries and path transitions. Keep this value stable because the same
    // sequence is used for duplicate checks and route registration.
    private const ulong PreferredAddressConnectionIdSequence = 1;
    private const ulong ApplicationSendDelayMicros = 1_000UL;
    private const ulong DefaultMaxAckDelayMicros = QuicMaxAckDelayPolicy.DefaultMaxAckDelayMicros;
    private const string CongestionControllerExhaustedMessage = "The congestion controller cannot send another ordinary packet.";
    private static readonly InvalidOperationException CongestionControllerExhaustedException =
        new(CongestionControllerExhaustedMessage);
    // Hold slightly underfilled application writes long enough to coalesce a follow-up FIN
    // or sibling frame into one 1-RTT packet instead of emitting a second tiny packet.
    private const int ApplicationSendDelayThresholdBytes = 32;
    private const int ApplicationPacketNumberLengthBytes = 4;
    private const int ApplicationSendBatchAckHeadroomBytes = 64;
    private const int HandshakeEgressChunkBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
    private const int MaximumBufferedEstablishmentHandshakePackets = 8;
    private const int InitialHostedTimerUpdateCapacity = 8;
    private const int InitialHostedSendDatagramUpdateCapacity = 16;
    private const byte OutboundStreamControlFrameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
    private const int ApplicationMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int MaximumStreamWriteChunkBytes = 32 * 1024;
    private readonly IMonotonicClock clock;
    private readonly QuicConnectionSendRuntime sendRuntime;
    private readonly QuicRecoveryController recoveryController;
    private readonly QuicConnectionStreamRegistry streamRegistry;
    private readonly Channel<ulong> inboundStreamIds;
    private readonly Channel<ReadOnlyMemory<byte>>? inboundDatagrams;
    private readonly Channel<QuicConnectionEvent> inbox;
    private readonly ConcurrentDictionary<long, StreamOpenRequestCompletionSource> pendingStreamOpenRequests = new();
    private readonly Dictionary<long, StreamActionRequestCompletionSource> pendingStreamActionRequests = new();
    private readonly ConcurrentDictionary<long, DatagramSendRequestCompletionSource> pendingDatagramSendRequests = new();
    private readonly ConcurrentQueue<StreamOpenRequestCompletionSource> streamOpenRequestCompletionSourcePool = new();
    private readonly ConcurrentQueue<StreamActionRequestCompletionSource> streamActionRequestCompletionSourcePool = new();
    private readonly ConcurrentQueue<DatagramSendRequestCompletionSource> datagramSendRequestCompletionSourcePool = new();
    private readonly ConcurrentQueue<InboundStreamAcceptCompletionSource> inboundStreamAcceptCompletionSourcePool = new();
    private readonly object pendingStreamActionRequestsGate = new();
    private readonly object scheduledPeerStreamCapacityReleaseGate = new();
    private readonly object scheduledFlowControlCreditGate = new();
    private readonly QuicApplicationSendQueue applicationSendQueue = new();
    private readonly HashSet<ulong> pendingPeerStreamCapacityReleaseStreamIds = new(capacity: 16);
    private readonly HashSet<ulong> scheduledPeerStreamCapacityReleaseStreamIds = new(capacity: 16);
    private readonly Dictionary<ulong, QuicMaxStreamDataFrame> pendingFlowControlStreamCreditFrames = [];
    private readonly Dictionary<ulong, QuicMaxStreamDataFrame> scheduledFlowControlStreamCreditFrames = new(capacity: 16);
    private readonly QuicStreamObserverDirectory streamObservers = new();
    private readonly QuicConnectionIssuedConnectionIdState issuedConnectionIdState = new();
    private readonly Dictionary<string, QuicConnectionNewTokenEmissionRecord> newTokenEmissionsByRemoteAddress = new(StringComparer.Ordinal);
    private readonly List<BufferedEstablishmentHandshakePacket> bufferedEstablishmentHandshakePackets = new(MaximumBufferedEstablishmentHandshakePackets);
    private readonly QuicConnectionPeerConnectionIdState peerConnectionIdState = new();
    private readonly long timeOriginTicks;
    private readonly QuicHandshakeFlowCoordinator handshakeFlowCoordinator;
    private readonly QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot;
    private readonly QuicDetachedResumptionTicketSnapshot? dormantDetachedResumptionTicketSnapshot;
    private readonly QuicConnectionDiagnosticsState diagnosticsState;
    private readonly QuicConnectionApplicationAckState applicationAckState = new();
    private readonly QuicTransportTlsBridgeState tlsState;
    private readonly QuicTlsTransportBridgeDriver tlsBridgeDriver;
    private readonly Action<QuicTlsKeyLogSecret>? tlsKeyLogSecretObserver;
    private readonly bool enableInitialPeerUsableConnectionId;
    private readonly QuicConnectionStreamActionEvent streamCapacityReleaseEvent;
    private QuicMaxDataFrame? pendingFlowControlConnectionCreditFrame;
    private QuicMaxDataFrame? scheduledFlowControlConnectionCreditFrame;
    private QuicConnectionVersionProfile versionProfile;
    private readonly QuicAddressValidationTokenProtector addressValidationTokenProtector;
    private readonly bool allowClientPeerInitialReplacementBeforeTranscript;
    private QuicInitialPacketProtection? initialPacketProtection;
    private QuicInitialPacketProtection? peerInitialPacketProtection;
    private QuicConnectionPathIdentity? bootstrapOutboundPathIdentity;
    private ReadOnlyMemory<byte>? initialBootstrapClientHelloBytes;
    private ReadOnlyMemory<byte>? ownedResumptionTicketBytes;
    private ReadOnlyMemory<byte>? ownedResumptionTicketNonce;
    private uint? ownedResumptionTicketLifetimeSeconds;
    private uint? ownedResumptionTicketAgeAdd;
    private uint? ownedResumptionTicketMaxEarlyDataSize;
    private QuicTransportParameters? ownedResumptionTicketPeerTransportParameters;
    private long? ownedResumptionTicketCapturedAtTicks;
    private ReadOnlyMemory<byte>? initialAddressValidationToken;
    private ReadOnlyMemory<byte>? resumptionMasterSecret;
    private ReadOnlyMemory<byte>? retrySourceConnectionId;
    private ReadOnlyMemory<byte>? retryToken;
    private ReadOnlyMemory<byte>? observedPeerInitialSourceConnectionId;
    private ReadOnlyMemory<byte>? observedPeerInitialCryptoFrameData;
    private bool retryBootstrapPendingReplay;
    private bool zeroRttPacketSent;
    private bool handshakeDonePacketSent;
    private bool localCloseEffectsPending;
    private bool hasSuccessfullyProcessedAnotherPacket;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;
    private bool peerHandshakeTranscriptCompleted;
    private bool handshakeConfirmed;
    private QuicConnectionTransportState transportFlags;
    private readonly QuicConnectionPathState pathState;
    private readonly QuicConnectionLifecycleTimerState lifecycleTimerState = new();
    private List<QuicConnectionTimerUpdate>? pendingHostedTimerUpdates;
    private List<QuicConnectionSendDatagramUpdate>? pendingHostedSendDatagramUpdates;
    private int pendingHostedSendDatagramUpdateIndex;
    private bool suppressHostedTimerEffectObjects;
    private bool suppressHostedSendDatagramEffectObjects;
    private QuicConnectionTerminalState? terminalState;
    private QuicIdleTimeoutState? idleTimeoutState;
    private QuicConnectionPhase phase = QuicConnectionPhase.Establishing;
    private ulong? localMaxIdleTimeoutMicros;
    private ulong? peerMaxIdleTimeoutMicros;
    private ulong currentProbeTimeoutMicros;
    private long lastTransitionTicks;
    private ulong transitionSequence;
    private ulong largestObservedApplicationPacketNumber;
    private ulong lowestObservedCurrentOneRttKeyPhasePacketNumber;
    private ulong observedCurrentOneRttKeyPhase;
    private long nextStreamActionRequestId;
    private long nextDatagramSendRequestId;
    private long nextStreamObserverId;
    private Exception? inboundStreamQueueCompletionException;
    private Exception? inboundDatagramQueueCompletionException;
    private Func<QuicConnectionEvent, bool>? localApiEventDispatcher;
    private Func<bool>? streamCapacityReleaseDispatcher;
    private Func<bool>? flowControlCreditUpdateDispatcher;
    private Func<long, QuicStreamType, bool>? streamOpenDispatcher;
    private Func<long, QuicConnectionStreamActionKind, ulong, ReadOnlyMemory<byte>, bool>? streamWriteDispatcher;
    private Action<int, int>? streamCapacityObserver;
    private bool scheduledPeerStreamCapacityReleaseEventPending;
    private bool scheduledFlowControlCreditUpdatePending;
    private long? pendingApplicationSendDelayDueTicks;
    private ulong largestObservedInitialPacketNumber;
    private ulong largestObservedHandshakePacketNumber;
    private bool hasObservedApplicationPacketNumber;
    private bool hasObservedInitialPacketNumber;
    private bool hasObservedHandshakePacketNumber;
    private bool hasObservedCurrentOneRttKeyPhasePacketNumber;
    private bool pendingClientHandshakeAckProbeOnPto;

    private sealed class BufferedEstablishmentHandshakePacket : IDisposable
    {
        private byte[]? sourceConnectionIdOwner;
        private byte[]? datagramOwner;
        private readonly int sourceConnectionIdLength;
        private readonly int datagramLength;

        internal BufferedEstablishmentHandshakePacket(
            QuicConnectionPathIdentity pathIdentity,
            byte[] sourceConnectionIdOwner,
            int sourceConnectionIdLength,
            byte[] datagramOwner,
            int datagramLength,
            QuicEcnCounts? ecnCounts)
        {
            PathIdentity = pathIdentity;
            this.sourceConnectionIdOwner = sourceConnectionIdOwner;
            this.sourceConnectionIdLength = sourceConnectionIdLength;
            this.datagramOwner = datagramOwner;
            this.datagramLength = datagramLength;
            EcnCounts = ecnCounts;
        }

        internal QuicConnectionPathIdentity PathIdentity { get; }
        internal ReadOnlyMemory<byte> SourceConnectionId => sourceConnectionIdOwner is null
            ? ReadOnlyMemory<byte>.Empty
            : sourceConnectionIdOwner.AsMemory(0, sourceConnectionIdLength);
        internal ReadOnlyMemory<byte> Datagram => datagramOwner is null
            ? ReadOnlyMemory<byte>.Empty
            : datagramOwner.AsMemory(0, datagramLength);
        internal QuicEcnCounts? EcnCounts { get; }

        public void Dispose()
        {
            byte[]? sourceConnectionIdBuffer = sourceConnectionIdOwner;
            byte[]? datagramBuffer = datagramOwner;
            sourceConnectionIdOwner = null;
            datagramOwner = null;
            QuicBufferPool.ReturnBytes(sourceConnectionIdBuffer);
            QuicBufferPool.ReturnBytes(datagramBuffer);
        }
    }

    private sealed class StreamActionRequestCompletionSource : IValueTaskSource<bool>, IValueTaskSource
    {
        private readonly QuicConnectionRuntime owner;
        private ManualResetValueTaskSourceCore<bool> source;
        private CancellationTokenRegistration cancellationRegistration;
        private byte[]? ownedStreamData;
        private int completed;

        internal StreamActionRequestCompletionSource(QuicConnectionRuntime owner)
        {
            this.owner = owner;
            source = new ManualResetValueTaskSourceCore<bool>
            {
                RunContinuationsAsynchronously = true,
            };
        }

        internal ValueTask<bool> Task => new(this, source.Version);

        internal ValueTask UntypedTask => new(this, source.Version);

        internal void Prepare()
        {
            cancellationRegistration.Dispose();
            cancellationRegistration = default;
            ReleaseOwnedStreamData();
            ActionKind = default;
            StreamId = default;
            StreamDataLength = 0;
            SuppressTerminalException = false;
            completed = 0;
            source.Reset();
        }

        internal QuicConnectionStreamActionKind ActionKind { get; private set; }

        internal ulong StreamId { get; private set; }

        internal int StreamDataLength { get; private set; }

        internal bool SuppressTerminalException { get; set; }

        internal void ConfigureWrite(
            QuicConnectionStreamActionKind actionKind,
            ulong streamId,
            int streamDataLength)
        {
            ActionKind = actionKind;
            StreamId = streamId;
            StreamDataLength = streamDataLength;
        }

        internal void RegisterCancellation(long requestId, CancellationToken cancellationToken)
        {
            cancellationRegistration = cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.TryRemovePendingStreamActionRequest(requestId, out StreamActionRequestCompletionSource pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (owner, requestId, cancellationToken));
        }

        internal void DisposeCancellationRegistration()
        {
            cancellationRegistration.Dispose();
            cancellationRegistration = default;
        }

        internal bool HasOwnedStreamData => ownedStreamData is not null;

        internal ReadOnlySpan<byte> GetOwnedStreamDataSpan()
            => ownedStreamData is null
                ? ReadOnlySpan<byte>.Empty
                : ownedStreamData.AsSpan(0, StreamDataLength);

        internal ReadOnlyMemory<byte> GetOwnedStreamDataMemory()
            => ownedStreamData is null
                ? ReadOnlyMemory<byte>.Empty
                : new ReadOnlyMemory<byte>(ownedStreamData, 0, StreamDataLength);

        internal void EnsureOwnedStreamData(ReadOnlySpan<byte> streamData)
        {
            if (streamData.IsEmpty)
            {
                StreamDataLength = 0;
                return;
            }

            if (ownedStreamData is null || ownedStreamData.Length < streamData.Length)
            {
                ReleaseOwnedStreamData();
                ownedStreamData = QuicBufferPool.RentBytes(streamData.Length);
            }

            streamData.CopyTo(ownedStreamData);
            StreamDataLength = streamData.Length;
        }

        internal void ReleaseOwnedStreamData()
        {
            byte[]? ownedData = Interlocked.Exchange(ref ownedStreamData, null);
            if (ownedData is not null)
            {
                QuicBufferPool.ReturnBytes(ownedData);
            }
        }

        internal void TrySetResult()
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetResult(true);
        }

        internal void TrySetException(Exception exception)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetException(exception);
        }

        internal void TrySetTerminalException(Exception exception)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            if (SuppressTerminalException)
            {
                source.SetResult(false);
                return;
            }

            source.SetException(exception);
        }

        internal void TrySetCanceled(CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetException(new OperationCanceledException(cancellationToken));
        }

        bool IValueTaskSource<bool>.GetResult(short token)
        {
            try
            {
                return source.GetResult(token);
            }
            finally
            {
                DisposeCancellationRegistration();
                owner.ReturnStreamActionRequestCompletionSource(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource<bool>.GetStatus(short token)
        {
            return source.GetStatus(token);
        }

        void IValueTaskSource<bool>.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }

        void IValueTaskSource.GetResult(short token)
        {
            try
            {
                _ = source.GetResult(token);
            }
            finally
            {
                DisposeCancellationRegistration();
                owner.ReturnStreamActionRequestCompletionSource(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource.GetStatus(short token)
        {
            return source.GetStatus(token);
        }

        void IValueTaskSource.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }

    private sealed class StreamOpenRequestCompletionSource : IValueTaskSource<QuicStream>
    {
        private readonly QuicConnectionRuntime owner;
        private ManualResetValueTaskSourceCore<ulong> source;
        private CancellationTokenRegistration cancellationRegistration;
        private int completed;

        internal StreamOpenRequestCompletionSource(QuicConnectionRuntime owner)
        {
            this.owner = owner;
            source = new ManualResetValueTaskSourceCore<ulong>
            {
                RunContinuationsAsynchronously = true,
            };
        }

        internal ValueTask<QuicStream> Task => new(this, source.Version);

        internal QuicStreamType StreamType { get; set; }

        internal void Prepare(QuicStreamType streamType)
        {
            cancellationRegistration.Dispose();
            cancellationRegistration = default;
            StreamType = streamType;
            completed = 0;
            source.Reset();
        }

        internal void RegisterCancellation(long requestId, CancellationToken cancellationToken)
        {
            cancellationRegistration = cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.TryRemovePendingStreamOpenRequest(requestId, out StreamOpenRequestCompletionSource? pendingCompletion))
                {
                    pendingCompletion!.TrySetCanceled(token);
                }
            }, (owner, requestId, cancellationToken));
        }

        internal void DisposeCancellationRegistration()
        {
            cancellationRegistration.Dispose();
            cancellationRegistration = default;
        }

        internal void TrySetResult(ulong streamId)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetResult(streamId);
        }

        internal void TrySetException(Exception exception)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetException(exception);
        }

        internal void TrySetCanceled(CancellationToken cancellationToken)
            => TrySetException(new OperationCanceledException(cancellationToken));

        QuicStream IValueTaskSource<QuicStream>.GetResult(short token)
        {
            try
            {
                ulong streamId = source.GetResult(token);
                if (!owner.streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out _))
                {
                    throw new InvalidOperationException("The stream open completed without a committed stream state.");
                }

                return new QuicStream(owner.streamRegistry.Bookkeeping, streamId, owner);
            }
            finally
            {
                DisposeCancellationRegistration();
                owner.ReturnStreamOpenRequestCompletionSource(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource<QuicStream>.GetStatus(short token)
        {
            return source.GetStatus(token);
        }

        void IValueTaskSource<QuicStream>.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }

    private sealed class InboundStreamAcceptCompletionSource : IValueTaskSource<QuicStream>
    {
        private readonly QuicConnectionRuntime owner;
        private readonly Action completeRead;
        private ManualResetValueTaskSourceCore<QuicStream> source;
        private ValueTaskAwaiter<ulong> readAwaiter;

        internal InboundStreamAcceptCompletionSource(QuicConnectionRuntime owner)
        {
            this.owner = owner;
            completeRead = CompleteRead;
            source = new ManualResetValueTaskSourceCore<QuicStream>
            {
                RunContinuationsAsynchronously = true,
            };
        }

        internal ValueTask<QuicStream> Task => new(this, source.Version);

        internal void Prepare(ValueTask<ulong> readTask)
        {
            source.Reset();
            readAwaiter = readTask.GetAwaiter();
            readAwaiter.UnsafeOnCompleted(completeRead);
        }

        private void CompleteRead()
        {
            try
            {
                if (!readAwaiter.IsCompleted)
                {
                    throw new InvalidOperationException("The inbound stream read continuation ran before completion.");
                }

#pragma warning disable S5034 // The registered continuation runs only after the channel awaiter completes.
                ulong streamId = readAwaiter.GetResult();
#pragma warning restore S5034
                if (owner.terminalState is QuicConnectionTerminalState terminalState)
                {
                    throw CreateTerminalException(terminalState);
                }

                source.SetResult(new QuicStream(owner.streamRegistry.Bookkeeping, streamId, owner));
            }
            catch (ChannelClosedException ex)
            {
                Exception mappedException;
                if (owner.inboundStreamQueueCompletionException is Exception completionException)
                {
                    mappedException = completionException;
                }
                else if (owner.terminalState is QuicConnectionTerminalState terminalState)
                {
                    mappedException = CreateTerminalException(terminalState);
                }
                else if (owner.IsDisposed)
                {
                    mappedException = new ObjectDisposedException(nameof(QuicConnectionRuntime), ex);
                }
                else
                {
                    mappedException = ex;
                }

                source.SetException(mappedException);
            }
            catch (Exception ex)
            {
                source.SetException(ex);
            }
        }

        QuicStream IValueTaskSource<QuicStream>.GetResult(short token)
        {
            try
            {
                return source.GetResult(token);
            }
            finally
            {
                readAwaiter = default;
                owner.ReturnInboundStreamAcceptCompletionSource(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource<QuicStream>.GetStatus(short token)
        {
            return source.GetStatus(token);
        }

        void IValueTaskSource<QuicStream>.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }

    private sealed class DatagramSendRequestCompletionSource : IValueTaskSource
    {
        private readonly QuicConnectionRuntime owner;
        private ManualResetValueTaskSourceCore<bool> source;
        private int completed;

        internal DatagramSendRequestCompletionSource(QuicConnectionRuntime owner)
        {
            this.owner = owner;
            source = new ManualResetValueTaskSourceCore<bool>
            {
                RunContinuationsAsynchronously = true,
            };
        }

        internal ValueTask Task => new(this, source.Version);

        internal void Prepare()
        {
            completed = 0;
            source.Reset();
        }

        internal void TrySetResult()
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetResult(true);
        }

        internal void TrySetException(Exception exception)
        {
            if (Interlocked.Exchange(ref completed, 1) != 0)
            {
                return;
            }

            source.SetException(exception);
        }

        internal void TrySetCanceled(CancellationToken cancellationToken)
            => TrySetException(new OperationCanceledException(cancellationToken));

        void IValueTaskSource.GetResult(short token)
        {
            try
            {
                _ = source.GetResult(token);
            }
            finally
            {
                owner.ReturnDatagramSendRequestCompletionSource(this);
            }
        }

        ValueTaskSourceStatus IValueTaskSource.GetStatus(short token)
        {
            return source.GetStatus(token);
        }

        void IValueTaskSource.OnCompleted(
            Action<object?> continuation,
            object? state,
            short token,
            ValueTaskSourceOnCompletedFlags flags)
        {
            source.OnCompleted(continuation, state, token, flags);
        }
    }

    private StreamOpenRequestCompletionSource RentStreamOpenRequestCompletionSource(QuicStreamType streamType)
    {
        if (!streamOpenRequestCompletionSourcePool.TryDequeue(out StreamOpenRequestCompletionSource? typedSource))
        {
            typedSource = new StreamOpenRequestCompletionSource(this);
        }

        typedSource.Prepare(streamType);
        return typedSource;
    }

    private void ReturnStreamOpenRequestCompletionSource(StreamOpenRequestCompletionSource completionSource)
    {
        streamOpenRequestCompletionSourcePool.Enqueue(completionSource);
    }

    private InboundStreamAcceptCompletionSource RentInboundStreamAcceptCompletionSource(ValueTask<ulong> readTask)
    {
        if (!inboundStreamAcceptCompletionSourcePool.TryDequeue(out InboundStreamAcceptCompletionSource? completionSource))
        {
            completionSource = new InboundStreamAcceptCompletionSource(this);
        }

        completionSource.Prepare(readTask);
        return completionSource;
    }

    private void ReturnInboundStreamAcceptCompletionSource(InboundStreamAcceptCompletionSource completionSource)
    {
        inboundStreamAcceptCompletionSourcePool.Enqueue(completionSource);
    }

    private StreamActionRequestCompletionSource RentStreamActionRequestCompletionSource()
    {
        if (!streamActionRequestCompletionSourcePool.TryDequeue(out StreamActionRequestCompletionSource? typedSource))
        {
            typedSource = new StreamActionRequestCompletionSource(this);
        }

        typedSource.Prepare();
        return typedSource;
    }

    private void ReturnStreamActionRequestCompletionSource(StreamActionRequestCompletionSource completionSource)
    {
        completionSource.ReleaseOwnedStreamData();
        streamActionRequestCompletionSourcePool.Enqueue(completionSource);
    }

    private DatagramSendRequestCompletionSource RentDatagramSendRequestCompletionSource()
    {
        if (!datagramSendRequestCompletionSourcePool.TryDequeue(out DatagramSendRequestCompletionSource? typedSource))
        {
            typedSource = new DatagramSendRequestCompletionSource(this);
        }

        typedSource.Prepare();
        return typedSource;
    }

    private void ReturnDatagramSendRequestCompletionSource(DatagramSendRequestCompletionSource completionSource)
    {
        datagramSendRequestCompletionSourcePool.Enqueue(completionSource);
    }

    private bool TryAddPendingStreamActionRequest(long requestId, StreamActionRequestCompletionSource completionSource)
    {
        lock (pendingStreamActionRequestsGate)
        {
            return pendingStreamActionRequests.TryAdd(requestId, completionSource);
        }
    }

    private bool TryRemovePendingStreamActionRequest(long requestId, out StreamActionRequestCompletionSource completionSource)
    {
        lock (pendingStreamActionRequestsGate)
        {
            bool removed = pendingStreamActionRequests.Remove(requestId, out StreamActionRequestCompletionSource? removedCompletion);
            completionSource = removedCompletion!;
            return removed;
        }
    }

    public QuicConnectionRuntime(
        QuicConnectionStreamState bookkeeping,
        IMonotonicClock? clock = null,
        int maximumCandidatePaths = 8,
        int maximumRecentlyValidatedPaths = 8,
        ulong currentProbeTimeoutMicros = QuicRttEstimator.DefaultInitialRttMicros,
        ReadOnlyMemory<byte> localHandshakePrivateKey = default,
        ReadOnlyMemory<byte> pinnedPeerLeafCertificateSha256 = default,
        ReadOnlyMemory<byte> localServerLeafCertificateDer = default,
        ReadOnlyMemory<byte> localServerLeafSigningPrivateKey = default,
        QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot = null,
        RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null,
        SslClientAuthenticationOptions? clientAuthenticationOptions = null,
        QuicTlsRole tlsRole = QuicTlsRole.Client,
        QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot = null,
        IQuicDiagnosticsSink? diagnosticsSink = null,
        bool enableRandomizedSpinBitSelection = false,
        uint[]? supportedVersions = null,
        ulong maximumLocallyIssuedConnectionIds = ulong.MaxValue,
        QuicAddressValidationTokenProtector? addressValidationTokenProtector = null,
        bool allowClientPeerInitialReplacementBeforeTranscript = false,
        QuicTlsCipherSuite? selectedCipherSuite = null,
        bool enableServerResumptionTickets = false,
        bool enableServerEarlyData = false,
        QuicServerResumptionTicketStore? serverResumptionTicketStore = null,
        Action<QuicTlsKeyLogSecret>? tlsKeyLogSecretObserver = null,
        int maximumInboundDatagramQueueSize = 1024,
        bool enableInitialPeerUsableConnectionId = true,
        QuicCongestionControlAlgorithm congestionControlAlgorithm = QuicCongestionControlAlgorithm.NewReno)
    {
        this.clock = clock ?? new MonotonicClock();
        timeOriginTicks = this.clock.Ticks;
        streamCapacityReleaseEvent = new QuicConnectionStreamActionEvent(
            timeOriginTicks,
            RequestId: 0,
            QuicConnectionStreamActionKind.ReleaseCapacity);
        sendRuntime = new QuicConnectionSendRuntime(congestionControlAlgorithm: congestionControlAlgorithm);
        recoveryController = new QuicRecoveryController();
        streamRegistry = new QuicConnectionStreamRegistry(bookkeeping);
        this.clientCertificatePolicySnapshot = clientCertificatePolicySnapshot;
        diagnosticsState = new QuicConnectionDiagnosticsState(diagnosticsSink);
        uint[] supportedVersionSnapshot = supportedVersions is { Length: > 0 }
            ? (uint[])supportedVersions.Clone()
            : [QuicVersionNegotiation.Version1];
        versionProfile = new QuicConnectionVersionProfile(supportedVersionSnapshot);
        handshakeFlowCoordinator = new QuicHandshakeFlowCoordinator(
            enableRandomizedSpinBitSelection: enableRandomizedSpinBitSelection,
            initialPacketVersion: versionProfile.SelectedVersion);
        if (detachedResumptionTicketSnapshot is not null && tlsRole != QuicTlsRole.Client)
        {
            throw new ArgumentException("Detached resumption ticket snapshots are only supported for the client role.", nameof(detachedResumptionTicketSnapshot));
        }

        dormantDetachedResumptionTicketSnapshot = detachedResumptionTicketSnapshot;
        this.tlsKeyLogSecretObserver = tlsKeyLogSecretObserver;
        this.enableInitialPeerUsableConnectionId = enableInitialPeerUsableConnectionId;
        tlsState = new QuicTransportTlsBridgeState(tlsRole);
        tlsBridgeDriver = new QuicTlsTransportBridgeDriver(
            tlsRole,
            tlsState,
            localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256,
            localServerLeafCertificateDer,
            localServerLeafSigningPrivateKey,
            clientCertificatePolicySnapshot,
            remoteCertificateValidationCallback,
            clientAuthenticationOptions,
            selectedCipherSuite,
            enableServerResumptionTickets,
            enableServerEarlyData,
            serverResumptionTicketStore,
            emitKeyLogSecrets: tlsKeyLogSecretObserver is not null,
            transportVersion: versionProfile.SelectedVersion);
        inbox = Channel.CreateUnbounded<QuicConnectionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
        inboundStreamIds = Channel.CreateUnbounded<ulong>(new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false,
            AllowSynchronousContinuations = false,
        });
        if (maximumInboundDatagramQueueSize < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumInboundDatagramQueueSize));
        }

        inboundDatagrams = maximumInboundDatagramQueueSize == 0
            ? null
            : Channel.CreateBounded<ReadOnlyMemory<byte>>(new BoundedChannelOptions(maximumInboundDatagramQueueSize)
            {
                SingleReader = false,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false,
            });

        if (maximumCandidatePaths < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCandidatePaths));
        }

        if (maximumRecentlyValidatedPaths < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumRecentlyValidatedPaths));
        }

        if (currentProbeTimeoutMicros == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(currentProbeTimeoutMicros));
        }

        MaximumCandidatePaths = maximumCandidatePaths;
        MaximumRecentlyValidatedPaths = maximumRecentlyValidatedPaths;
        MaximumLocallyIssuedConnectionIds = maximumLocallyIssuedConnectionIds;
        pathState = new QuicConnectionPathState(maximumRecentlyValidatedPaths);
        this.currentProbeTimeoutMicros = currentProbeTimeoutMicros;
        this.addressValidationTokenProtector = addressValidationTokenProtector ?? QuicAddressValidationTokenProtector.CreateEphemeral();
        this.allowClientPeerInitialReplacementBeforeTranscript = allowClientPeerInitialReplacementBeforeTranscript;
        QuicMetrics.RecordConnectionStarted(tlsState.Role);
    }

    public QuicConnectionPhase Phase => phase;

    public QuicConnectionSendingMode SendingMode => phase switch
    {
        QuicConnectionPhase.Establishing => QuicConnectionSendingMode.Ordinary,
        QuicConnectionPhase.Active => QuicConnectionSendingMode.Ordinary,
        QuicConnectionPhase.Closing => QuicConnectionSendingMode.CloseOnly,
        QuicConnectionPhase.Draining => QuicConnectionSendingMode.None,
        QuicConnectionPhase.Discarded => QuicConnectionSendingMode.None,
        _ => throw new InvalidOperationException($"Unknown connection phase {phase}."),
    };

    public bool CanSendOrdinaryPackets => SendingMode == QuicConnectionSendingMode.Ordinary;

    public bool PeerHandshakeTranscriptCompleted => peerHandshakeTranscriptCompleted;

    internal bool HandshakeConfirmed => tlsState.Role == QuicTlsRole.Server
        ? peerHandshakeTranscriptCompleted
        : handshakeConfirmed;

    public QuicConnectionTransportState TransportFlags => transportFlags;

    public QuicConnectionActivePathRecord? ActivePath => activePath;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> CandidatePaths => candidatePaths;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> RecentlyValidatedPaths => recentlyValidatedPaths;

    public QuicConnectionTimerDeadlineState TimerState => lifecycleTimerState.TimerState;

    public QuicConnectionTerminalState? TerminalState => terminalState;

    public QuicIdleTimeoutState? IdleTimeoutState => idleTimeoutState;

    public ulong? LocalMaxIdleTimeoutMicros => localMaxIdleTimeoutMicros;

    public ulong? PeerMaxIdleTimeoutMicros => peerMaxIdleTimeoutMicros;

    public ulong CurrentProbeTimeoutMicros => currentProbeTimeoutMicros;

    public string? LastValidatedRemoteAddress => lastValidatedRemoteAddress;

    internal QuicConnectionVersionProfile VersionProfile => versionProfile;

    internal QuicHandshakeFlowCoordinator HandshakeFlowCoordinator => handshakeFlowCoordinator;

    internal QuicTlsTransportBridgeDriver TlsBridgeDriver => tlsBridgeDriver;

    internal IQuicDiagnosticsSink DiagnosticsSink => diagnosticsState.Sink;

    internal bool DiagnosticsEnabled => diagnosticsState.IsEnabled;

    private bool diagnosticsEnabled => diagnosticsState.IsEnabled;

    internal ReadOnlyMemory<byte>? InitialBootstrapClientHelloBytes => initialBootstrapClientHelloBytes;

    internal ReadOnlyMemory<byte> CurrentPeerDestinationConnectionId
    {
        get
        {
            if (PeerRequestedZeroLengthConnectionId())
            {
                return ReadOnlyMemory<byte>.Empty;
            }

            if (!peerConnectionIdState.CurrentDestinationConnectionId.IsEmpty)
            {
                return peerConnectionIdState.CurrentDestinationConnectionId;
            }

            if (preferredAddressOldPathIdentity.HasValue
                && tlsState.PeerTransportParameters?.PreferredAddress is QuicPreferredAddress preferredAddress)
            {
                return preferredAddress.ConnectionId;
            }

            return handshakeFlowCoordinator.DestinationConnectionId;
        }
    }

    private bool LocallySelectedZeroLengthConnectionId()
    {
        return tlsState.LocalTransportParameters?.InitialSourceConnectionId is { Length: 0 };
    }

    internal ReadOnlyMemory<byte> CurrentHandshakeSourceConnectionId
        => handshakeFlowCoordinator.SourceConnectionId;

    public bool HasValidatedPath => pathState.HasValidatedPath;

    public QuicConnectionStreamRegistry StreamRegistry => streamRegistry;

    public int MaximumCandidatePaths { get; }

    public int MaximumRecentlyValidatedPaths { get; }

    public ulong MaximumLocallyIssuedConnectionIds { get; }

    public long LastTransitionTicks => lastTransitionTicks;

    public ulong TransitionSequence => transitionSequence;

    internal bool IsInboxConsumerRunning => Volatile.Read(ref consumerStarted) != 0;

    internal bool IsDisposed => Volatile.Read(ref disposed) != 0;

    internal bool HasTerminalStreamOperation => IsDisposed || terminalState is not null;

    internal bool HasProcessingTask => processingTask is not null;

    internal void SetPhaseForTesting(QuicConnectionPhase phase)
    {
        this.phase = phase;
    }

    internal IMonotonicClock Clock => clock;

    internal QuicConnectionSendRuntime SendRuntime => sendRuntime;

    internal QuicTransportTlsBridgeState TlsState => tlsState;

    internal QuicRecoveryController RecoveryController => recoveryController;

    internal ReadOnlyMemory<byte> OwnedResumptionTicketBytes => ownedResumptionTicketBytes ?? ReadOnlyMemory<byte>.Empty;

    internal bool HasOwnedResumptionTicket => ownedResumptionTicketBytes is not null;

    internal ReadOnlyMemory<byte> OwnedResumptionTicketNonce => ownedResumptionTicketNonce ?? ReadOnlyMemory<byte>.Empty;

    internal uint? OwnedResumptionTicketLifetimeSeconds => ownedResumptionTicketLifetimeSeconds;

    internal uint? OwnedResumptionTicketAgeAdd => ownedResumptionTicketAgeAdd;

    internal long? OwnedResumptionTicketCapturedAtTicks => ownedResumptionTicketCapturedAtTicks;

    internal ReadOnlyMemory<byte> ResumptionMasterSecret => resumptionMasterSecret ?? tlsState.ResumptionMasterSecret;

    internal bool HasResumptionMasterSecret => resumptionMasterSecret is not null || tlsState.HasResumptionMasterSecret;

    internal QuicTlsResumptionAttemptDisposition ResumptionAttemptDisposition => tlsState.ResumptionAttemptDisposition;

    internal bool IsEarlyDataAdmissionOpen =>
        tlsState.Role == QuicTlsRole.Server
        && phase == QuicConnectionPhase.Establishing
        && tlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out _);

    internal QuicClientCertificatePolicySnapshot? ClientCertificatePolicySnapshot => clientCertificatePolicySnapshot;

    internal QuicDetachedResumptionTicketSnapshot? DormantDetachedResumptionTicketSnapshot => dormantDetachedResumptionTicketSnapshot;

    internal bool HasDormantDetachedResumptionTicketSnapshot => dormantDetachedResumptionTicketSnapshot is not null;

    /// <summary>
    /// Gets whether the dormant detached carrier is ready for a future 0-RTT attempt.
    /// </summary>
    internal bool HasDormantEarlyDataAttemptReadiness =>
        dormantDetachedResumptionTicketSnapshot is not null
        && dormantDetachedResumptionTicketSnapshot.HasResumptionCredentialMaterial
        && dormantDetachedResumptionTicketSnapshot.HasEarlyDataPrerequisiteMaterial;

    internal Func<QuicConnectionEvent, bool>? LocalApiEventDispatcher => localApiEventDispatcher;

    internal Action<int, int>? StreamCapacityObserver => streamCapacityObserver;

    internal QuicInitialPacketProtection? InitialPacketProtection => initialPacketProtection;

    internal QuicInitialPacketProtection? PeerInitialPacketProtection => peerInitialPacketProtection;

    internal int BufferedEstablishmentHandshakePacketCount => bufferedEstablishmentHandshakePackets.Count;

    internal Dictionary<ulong, byte[]> StatelessResetTokensByConnectionId => issuedConnectionIdState.StatelessResetTokensByConnectionId;

    internal Dictionary<string, QuicConnectionNewTokenEmissionRecord> NewTokenEmissionsByRemoteAddress => newTokenEmissionsByRemoteAddress;

    internal void MarkHandshakeDonePacketSentForTests()
    {
        handshakeDonePacketSent = true;
    }

    internal bool TryConfigurePeerInitialPacketProtection(
        uint version,
        ReadOnlySpan<byte> clientInitialDestinationConnectionId)
    {
        if (tlsState.Role != QuicTlsRole.Server)
        {
            return false;
        }

        if (peerInitialPacketProtection is not null)
        {
            return peerInitialPacketProtection.Version == version;
        }

        if (!QuicInitialPacketProtection.TryCreate(
            tlsState.Role,
            version,
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtection protection))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TrySetInitialDestinationConnectionId(clientInitialDestinationConnectionId))
        {
            return false;
        }

        peerInitialPacketProtection = protection;
        return true;
    }

    internal bool TryConfigureInitialPacketProtection(ReadOnlySpan<byte> clientInitialDestinationConnectionId)
    {
        return TryConfigureInitialPacketProtection(versionProfile.SelectedVersion, clientInitialDestinationConnectionId);
    }

    internal bool TryConfigureInitialPacketProtection(uint version, ReadOnlySpan<byte> clientInitialDestinationConnectionId)
    {
        if (initialPacketProtection is not null)
        {
            return initialPacketProtection.Version == version;
        }

        if (!QuicInitialPacketProtection.TryCreate(
            tlsState.Role,
            version,
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtection protection))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TrySetInitialDestinationConnectionId(clientInitialDestinationConnectionId))
        {
            return false;
        }

        initialPacketProtection = protection;
        return true;
    }

    internal bool TryAdoptNegotiatedVersion(uint negotiatedVersion)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || negotiatedVersion == versionProfile.SelectedVersion)
        {
            return negotiatedVersion == versionProfile.SelectedVersion;
        }

        if (!QuicVersionNegotiation.AreCompatibleVersions(versionProfile.SelectedVersion, negotiatedVersion)
            || initialPacketProtection is null
            || handshakeFlowCoordinator.InitialDestinationConnectionId.IsEmpty
            || !QuicVersionNegotiation.TryMoveVersionToFront(
                versionProfile.SupportedVersions.Span,
                negotiatedVersion,
                out uint[] reorderedSupportedVersions))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TrySetPacketVersion(negotiatedVersion)
            || !tlsBridgeDriver.TryUpdateTransportVersion(negotiatedVersion)
            || !QuicInitialPacketProtection.TryCreate(
                tlsState.Role,
                negotiatedVersion,
                handshakeFlowCoordinator.InitialDestinationConnectionId.Span,
                out QuicInitialPacketProtection negotiatedProtection))
        {
            return false;
        }

        versionProfile = new QuicConnectionVersionProfile(reorderedSupportedVersions);
        initialPacketProtection = negotiatedProtection;
        return true;
    }

    internal bool TryGetIncomingInitialPacketProtection(
        uint packetVersion,
        out QuicInitialPacketProtection protection)
    {
        protection = default!;

        if (tlsState.Role == QuicTlsRole.Server)
        {
            if (peerInitialPacketProtection is { } peerProtection
                && peerProtection.Version == packetVersion)
            {
                protection = peerProtection;
                return true;
            }

            if (initialPacketProtection is { } currentProtection
                && currentProtection.Version == packetVersion)
            {
                protection = currentProtection;
                return true;
            }

            return false;
        }

        if (initialPacketProtection is { } currentClientProtection
            && currentClientProtection.Version == packetVersion)
        {
            protection = currentClientProtection;
            return true;
        }

        if (!TryAdoptNegotiatedVersion(packetVersion)
            || initialPacketProtection is not { } adoptedProtection)
        {
            return false;
        }

        protection = adoptedProtection;
        return true;
    }

    internal bool TryConfigureRetryInitialPacketProtection(ReadOnlySpan<byte> retrySelectedDestinationConnectionId)
    {
        return TryConfigureRetryInitialPacketProtection(versionProfile.SelectedVersion, retrySelectedDestinationConnectionId);
    }

    internal bool TryConfigureRetryInitialPacketProtection(uint version, ReadOnlySpan<byte> retrySelectedDestinationConnectionId)
    {
        if (!QuicInitialPacketProtection.TryCreate(
            tlsState.Role,
            version,
            retrySelectedDestinationConnectionId,
            out QuicInitialPacketProtection protection))
        {
            return false;
        }

        initialPacketProtection = protection;
        return true;
    }

    internal bool TryExportDetachedResumptionTicketSnapshot(out QuicDetachedResumptionTicketSnapshot? detachedResumptionTicketSnapshot)
    {
        _ = TryCaptureResumptionMasterSecret();

        if (tlsState.Role != QuicTlsRole.Client
            || ownedResumptionTicketBytes is null
            || ownedResumptionTicketNonce is null
            || ownedResumptionTicketLifetimeSeconds is null
            || ownedResumptionTicketAgeAdd is null
            || ownedResumptionTicketCapturedAtTicks is null
            || !HasResumptionMasterSecret)
        {
            detachedResumptionTicketSnapshot = null;
            return false;
        }

        detachedResumptionTicketSnapshot = new QuicDetachedResumptionTicketSnapshot(
            ownedResumptionTicketBytes.Value,
            ownedResumptionTicketNonce.Value,
            ownedResumptionTicketLifetimeSeconds.Value,
            ownedResumptionTicketAgeAdd.Value,
            ownedResumptionTicketCapturedAtTicks.Value,
            ResumptionMasterSecret,
            ownedResumptionTicketMaxEarlyDataSize,
            ownedResumptionTicketPeerTransportParameters);
        return true;
    }

    internal bool TrySetBootstrapOutboundPath(QuicConnectionPathIdentity pathIdentity)
    {
        if (bootstrapOutboundPathIdentity.HasValue)
        {
            return EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(bootstrapOutboundPathIdentity.Value, pathIdentity);
        }

        bootstrapOutboundPathIdentity = pathIdentity;
        return true;
    }

    internal bool TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return handshakeFlowCoordinator.TrySetHandshakeDestinationConnectionId(connectionId);
    }

    internal bool TrySetHandshakeSourceConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return handshakeFlowCoordinator.TrySetSourceConnectionId(connectionId);
    }

    internal bool TryConfigureLocalApplicationProtocols(IReadOnlyList<SslApplicationProtocol> applicationProtocols)
    {
        return tlsBridgeDriver.TryConfigureLocalApplicationProtocols(applicationProtocols);
    }

    internal bool TryConfigureServerResumptionTicketIssuance(bool enabled)
    {
        return tlsBridgeDriver.TryConfigureServerResumptionTicketIssuance(enabled);
    }

    internal bool TryConfigureServerEarlyData(bool enabled)
    {
        return tlsBridgeDriver.TryConfigureServerEarlyData(enabled);
    }

    internal bool TryConfigureServerAuthenticationMaterial(
        ReadOnlyMemory<byte> certificateDer,
        ReadOnlyMemory<byte> signingPrivateKey,
        bool clientCertificateRequired = false,
        X509ChainPolicy? serverClientCertificateChainPolicy = null,
        X509RevocationMode serverClientCertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        RemoteCertificateValidationCallback? serverRemoteCertificateValidationCallback = null)
    {
        return tlsBridgeDriver.TryConfigureServerAuthenticationMaterial(
            certificateDer,
            signingPrivateKey,
            clientCertificateRequired,
            serverClientCertificateChainPolicy,
            serverClientCertificateRevocationCheckMode,
            serverRemoteCertificateValidationCallback);
    }

    /// <summary>
    /// Posts a network-originated event to the connection inbox.
    /// </summary>
    public bool TryPostNetworkEvent(QuicConnectionEvent networkEvent)
    {
        return TryPostEvent(networkEvent);
    }

    /// <summary>
    /// Posts a timer-originated event to the connection inbox.
    /// </summary>
    public bool TryPostTimerEvent(QuicConnectionTimerExpiredEvent timerEvent)
    {
        return TryPostEvent(timerEvent);
    }

    /// <summary>
    /// Posts a local API event to the connection inbox.
    /// </summary>
    public bool TryPostLocalApiEvent(QuicConnectionEvent localApiEvent)
    {
        ArgumentNullException.ThrowIfNull(localApiEvent);
        return localApiEventDispatcher?.Invoke(localApiEvent) ?? TryPostEvent(localApiEvent);
    }

    internal void SetLocalApiEventDispatcher(Func<QuicConnectionEvent, bool> dispatcher)
    {
        localApiEventDispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        streamCapacityReleaseDispatcher = null;
        flowControlCreditUpdateDispatcher = null;
        streamOpenDispatcher = null;
        streamWriteDispatcher = null;
    }

    internal void SetStreamCapacityReleaseDispatcher(Func<bool> dispatcher)
    {
        streamCapacityReleaseDispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    internal void SetFlowControlCreditUpdateDispatcher(Func<bool> dispatcher)
    {
        flowControlCreditUpdateDispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    internal void SetStreamOpenDispatcher(Func<long, QuicStreamType, bool> dispatcher)
    {
        streamOpenDispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    internal void SetStreamWriteDispatcher(Func<long, QuicConnectionStreamActionKind, ulong, ReadOnlyMemory<byte>, bool> dispatcher)
    {
        streamWriteDispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
    }

    internal void SetStreamCapacityObserver(Action<int, int>? observer)
    {
        streamCapacityObserver = observer;
    }

    internal void TryQueueStreamCapacityRelease(ulong streamId)
    {
        if (IsDisposed || terminalState is not null)
        {
            return;
        }

        bool shouldPostEvent = TryMarkPeerStreamCapacityReleaseScheduled(streamId);
        if (!shouldPostEvent)
        {
            return;
        }

        bool posted = streamCapacityReleaseDispatcher?.Invoke()
            ?? TryPostLocalApiEvent(streamCapacityReleaseEvent);
        if (!posted)
        {
            ClearPeerStreamCapacityReleaseEventScheduled();
        }
    }

    private bool TryMarkPeerStreamCapacityReleaseScheduled(ulong streamId)
    {
        lock (scheduledPeerStreamCapacityReleaseGate)
        {
            scheduledPeerStreamCapacityReleaseStreamIds.Add(streamId);
            if (scheduledPeerStreamCapacityReleaseEventPending)
            {
                return false;
            }

            scheduledPeerStreamCapacityReleaseEventPending = true;
            return true;
        }
    }

    private void ClearPeerStreamCapacityReleaseScheduled(ulong streamId)
    {
        lock (scheduledPeerStreamCapacityReleaseGate)
        {
            scheduledPeerStreamCapacityReleaseStreamIds.Remove(streamId);
        }
    }

    private bool TryDeferScheduledPeerStreamCapacityReleases()
    {
        lock (scheduledPeerStreamCapacityReleaseGate)
        {
            if (scheduledPeerStreamCapacityReleaseStreamIds.Count == 0)
            {
                return false;
            }

            foreach (ulong streamId in scheduledPeerStreamCapacityReleaseStreamIds)
            {
                pendingPeerStreamCapacityReleaseStreamIds.Add(streamId);
            }

            scheduledPeerStreamCapacityReleaseStreamIds.Clear();
            scheduledPeerStreamCapacityReleaseEventPending = false;
            return true;
        }
    }

    private void ClearPeerStreamCapacityReleaseEventScheduled()
    {
        lock (scheduledPeerStreamCapacityReleaseGate)
        {
            scheduledPeerStreamCapacityReleaseEventPending = false;
        }
    }

    internal void TryQueueFlowControlCreditUpdate(
        QuicMaxDataFrame? maxDataFrame,
        QuicMaxStreamDataFrame? maxStreamDataFrame)
    {
        if (IsDisposed || terminalState is not null
            || (!maxDataFrame.HasValue && !maxStreamDataFrame.HasValue))
        {
            return;
        }

        bool shouldPostEvent = TryMarkFlowControlCreditUpdateScheduled(maxDataFrame, maxStreamDataFrame);
        if (!shouldPostEvent)
        {
            return;
        }

        bool posted = flowControlCreditUpdateDispatcher?.Invoke()
            ?? TryPostLocalApiEvent(new QuicConnectionFlowControlCreditUpdatedEvent(clock.Ticks));
        if (!posted)
        {
            ClearFlowControlCreditUpdateScheduled();
        }
    }

    private bool TryMarkFlowControlCreditUpdateScheduled(
        QuicMaxDataFrame? maxDataFrame,
        QuicMaxStreamDataFrame? maxStreamDataFrame)
    {
        lock (scheduledFlowControlCreditGate)
        {
            if (maxDataFrame is { } connectionCredit
                && (!scheduledFlowControlConnectionCreditFrame.HasValue
                    || connectionCredit.MaximumData > scheduledFlowControlConnectionCreditFrame.Value.MaximumData))
            {
                scheduledFlowControlConnectionCreditFrame = connectionCredit;
            }

            if (maxStreamDataFrame is { } streamCredit
                && (!scheduledFlowControlStreamCreditFrames.TryGetValue(streamCredit.StreamId, out QuicMaxStreamDataFrame pendingStreamCredit)
                    || streamCredit.MaximumStreamData > pendingStreamCredit.MaximumStreamData))
            {
                scheduledFlowControlStreamCreditFrames[streamCredit.StreamId] = streamCredit;
            }

            if (scheduledFlowControlCreditUpdatePending)
            {
                return false;
            }

            scheduledFlowControlCreditUpdatePending = true;
            return true;
        }
    }

    private void ClearFlowControlCreditUpdateScheduled()
    {
        lock (scheduledFlowControlCreditGate)
        {
            scheduledFlowControlCreditUpdatePending = false;
        }
    }

    private bool TryDeferScheduledFlowControlCreditUpdate()
    {
        lock (scheduledFlowControlCreditGate)
        {
            bool deferred = TryDeferFlowControlCreditUpdate(
                scheduledFlowControlConnectionCreditFrame,
                null);
            scheduledFlowControlConnectionCreditFrame = null;

            foreach (QuicMaxStreamDataFrame scheduledStreamCredit in scheduledFlowControlStreamCreditFrames.Values)
            {
                deferred |= TryDeferFlowControlCreditUpdate(null, scheduledStreamCredit);
            }

            scheduledFlowControlStreamCreditFrames.Clear();
            scheduledFlowControlCreditUpdatePending = false;
            return deferred;
        }
    }

    internal long RegisterStreamObserver(ulong streamId, Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        long observerId = Interlocked.Increment(ref nextStreamObserverId);

        if (!streamObservers.TryAdd(streamId, observerId, observer))
        {
            throw new InvalidOperationException("The connection runtime could not register the stream observer.");
        }

        NotifyCurrentStreamObserverState(streamId, observer, observerTarget: null);
        return observerId;
    }

    internal long RegisterStreamObserver(ulong streamId, IQuicStreamNotificationObserver observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        long observerId = Interlocked.Increment(ref nextStreamObserverId);

        if (!streamObservers.TryAdd(streamId, observerId, observer))
        {
            throw new InvalidOperationException("The connection runtime could not register the stream observer.");
        }

        NotifyCurrentStreamObserverState(streamId, observerAction: null, observerTarget: observer);
        return observerId;
    }

    private void NotifyCurrentStreamObserverState(
        ulong streamId,
        Action<QuicStreamNotification>? observerAction,
        IQuicStreamNotificationObserver? observerTarget)
    {
        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            NotifyStreamObserver(observerAction, observerTarget, new QuicStreamNotification(
                QuicStreamNotificationKind.ConnectionTerminated,
                CreateTerminalException(terminalStateValue)));
        }
        else
        {
            if (streamRegistry.Bookkeeping.TryGetReceiveAbortErrorCode(streamId, out ulong receiveAbortErrorCode))
            {
                NotifyStreamObserver(observerAction, observerTarget, new QuicStreamNotification(
                    QuicStreamNotificationKind.ReadAborted,
                    CreateStreamReadAbortedException(receiveAbortErrorCode)));
            }

            if (streamRegistry.Bookkeeping.TryGetSendAbortErrorCode(streamId, out ulong sendAbortErrorCode))
            {
                NotifyStreamObserver(observerAction, observerTarget, new QuicStreamNotification(
                    QuicStreamNotificationKind.WriteAborted,
                    CreateStreamWriteAbortedException(sendAbortErrorCode)));
            }
        }
    }

    private static void NotifyStreamObserver(
        Action<QuicStreamNotification>? observerAction,
        IQuicStreamNotificationObserver? observerTarget,
        QuicStreamNotification notification)
    {
        if (observerAction is not null)
        {
            observerAction(notification);
            return;
        }

        observerTarget!.OnStreamNotification(notification);
    }

    internal void UnregisterStreamObserver(ulong streamId, long observerId)
    {
        streamObservers.TryRemove(streamId, observerId);
    }

    internal ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            throw CreateTerminalException(terminalStateValue);
        }

        if (phase != QuicConnectionPhase.Active)
        {
            throw new InvalidOperationException(
                $"The connection is not established. Phase={phase} TerminalState={(terminalState.HasValue ? terminalState.Value.ToString() : "null")}");
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (!ApplicationReceiveDebugEnabled && inboundStreamIds.Reader.TryRead(out ulong streamId))
        {
            if (terminalState is QuicConnectionTerminalState completedTerminalState)
            {
                throw CreateTerminalException(completedTerminalState);
            }

            return new ValueTask<QuicStream>(new QuicStream(streamRegistry.Bookkeeping, streamId, this));
        }

        if (ApplicationReceiveDebugEnabled)
        {
            return AcceptInboundStreamDebugAsync(cancellationToken);
        }

        ValueTask<ulong> readTask = inboundStreamIds.Reader.ReadAsync(cancellationToken);
        if (readTask.IsCompletedSuccessfully)
        {
            streamId = readTask.GetAwaiter().GetResult();
            if (terminalState is QuicConnectionTerminalState completedTerminalState)
            {
                throw CreateTerminalException(completedTerminalState);
            }

            return new ValueTask<QuicStream>(new QuicStream(streamRegistry.Bookkeeping, streamId, this));
        }

        return RentInboundStreamAcceptCompletionSource(readTask).Task;
    }

    private async ValueTask<QuicStream> AcceptInboundStreamDebugAsync(CancellationToken cancellationToken)
    {
        try
        {
            ulong streamId = await inboundStreamIds.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (ApplicationReceiveDebugEnabled)
            {
                await Console.Error.WriteLineAsync($"app-rx accept-inbound-stream role={tlsState.Role} stream={streamId}.").ConfigureAwait(false);
            }

            if (terminalState is QuicConnectionTerminalState completedTerminalState)
            {
                throw CreateTerminalException(completedTerminalState);
            }

            return new QuicStream(streamRegistry.Bookkeeping, streamId, this);
        }
        catch (ChannelClosedException) when (inboundStreamQueueCompletionException is not null)
        {
            throw inboundStreamQueueCompletionException;
        }
        catch (ChannelClosedException) when (terminalState is QuicConnectionTerminalState completedTerminalState)
        {
            throw CreateTerminalException(completedTerminalState);
        }
        catch (ChannelClosedException ex) when (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntime), ex);
        }
    }

    internal ValueTask<QuicStream?> TryAcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        if (IsDisposed || terminalState is not null)
        {
            return new ValueTask<QuicStream?>((QuicStream?)null);
        }

        if (phase != QuicConnectionPhase.Active)
        {
            throw new InvalidOperationException(
                $"The connection is not established. Phase={phase} TerminalState={(terminalState.HasValue ? terminalState.Value.ToString() : "null")}");
        }

        if (cancellationToken.IsCancellationRequested)
        {
            return new ValueTask<QuicStream?>((QuicStream?)null);
        }

        if (!ApplicationReceiveDebugEnabled && inboundStreamIds.Reader.TryRead(out ulong streamId))
        {
            return new ValueTask<QuicStream?>(
                terminalState is not null
                    ? null
                    : new QuicStream(streamRegistry.Bookkeeping, streamId, this));
        }

        return TryAcceptInboundStreamSlowAsync(cancellationToken);
    }

    private async ValueTask<QuicStream?> TryAcceptInboundStreamSlowAsync(CancellationToken cancellationToken)
    {
        try
        {
            ulong streamId = await inboundStreamIds.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (ApplicationReceiveDebugEnabled)
            {
                await Console.Error.WriteLineAsync($"app-rx accept-inbound-stream role={tlsState.Role} stream={streamId}.").ConfigureAwait(false);
            }

            return terminalState is not null
                ? null
                : new QuicStream(streamRegistry.Bookkeeping, streamId, this);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (IsExpectedTerminalException(ex))
        {
            return null;
        }
        catch (ChannelClosedException) when (inboundStreamQueueCompletionException is not null)
        {
            if (IsExpectedTerminalException(inboundStreamQueueCompletionException))
            {
                return null;
            }

            throw inboundStreamQueueCompletionException;
        }
        catch (ChannelClosedException) when (terminalState is not null || IsDisposed)
        {
            return null;
        }
        catch (ChannelClosedException)
        {
            return null;
        }
    }

    internal ValueTask<QuicStream> OpenOutboundStreamAsync(
        QuicStreamType streamType,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            throw CreateTerminalException(terminalStateValue);
        }

        if (phase != QuicConnectionPhase.Active)
        {
            throw new InvalidOperationException(
                $"The connection is not established. Phase={phase} TerminalState={(terminalState.HasValue ? terminalState.Value.ToString() : "null")}");
        }

        if (streamType is not QuicStreamType.Unidirectional and not QuicStreamType.Bidirectional)
        {
            throw new ArgumentOutOfRangeException(nameof(streamType));
        }

        if (!tlsState.OneRttSendAuthorized)
        {
            throw new InvalidOperationException("The connection is not ready to open application streams.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamOpenRequestCompletionSource completion = RentStreamOpenRequestCompletionSource(streamType);
        if (!pendingStreamOpenRequests.TryAdd(requestId, completion))
        {
            pendingStreamOpenRequests.TryRemove(requestId, out _);
            ReturnStreamOpenRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the stream open request.");
        }

        if (cancellationToken.CanBeCanceled)
        {
            completion.RegisterCancellation(requestId, cancellationToken);
        }

        bool posted = streamOpenDispatcher?.Invoke(requestId, streamType)
            ?? TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
                clock.Ticks,
                requestId,
                QuicConnectionStreamActionKind.Open,
                StreamType: streamType));
        if (!posted)
        {
            if (TryRemovePendingStreamOpenRequest(requestId, out StreamOpenRequestCompletionSource? removedCompletion))
            {
                removedCompletion!.DisposeCancellationRegistration();
                ReturnStreamOpenRequestCompletionSource(removedCompletion!);
            }
            else
            {
                return OpenOutboundStreamPostFailureAsync(completion);
            }

            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream open request.");
        }

        return completion.Task;
    }

    private async ValueTask<QuicStream> OpenOutboundStreamPostFailureAsync(StreamOpenRequestCompletionSource completion)
    {
        _ = await completion.Task.ConfigureAwait(false);
        throw IsDisposed
            ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
            : new InvalidOperationException("The connection runtime could not queue the stream open request.");
    }

    internal ValueTask WriteStreamAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteStreamVoidAsyncCore(streamId, buffer, finishWrites: false, cancellationToken);

    internal ValueTask<bool> TryWriteStreamAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteStreamAsyncCore(streamId, buffer, finishWrites: false, suppressTerminalException: true, cancellationToken);

    internal ValueTask WriteFinalStreamAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteStreamVoidAsyncCore(streamId, buffer, finishWrites: true, cancellationToken);

    internal ValueTask<bool> TryWriteFinalStreamAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
        => WriteStreamAsyncCore(streamId, buffer, finishWrites: true, suppressTerminalException: true, cancellationToken);

    private static async ValueTask AwaitWriteStreamResultAsync(ValueTask<bool> writeTask)
    {
        _ = await writeTask.ConfigureAwait(false);
    }

    private ValueTask WriteStreamVoidAsyncCore(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (buffer.IsEmpty && !finishWrites)
        {
            return ValueTask.CompletedTask;
        }

        if (buffer.Length > MaximumStreamWriteChunkBytes)
        {
            return AwaitWriteStreamResultAsync(WriteStreamChunksAsync(
                streamId,
                buffer,
                finishWrites,
                suppressTerminalException: false,
                cancellationToken));
        }

        LogApplicationSend(
            $"app-tx api-write role={tlsState.Role} stream={streamId} length={buffer.Length} fin={finishWrites}.");

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        completion.ConfigureWrite(
            finishWrites ? QuicConnectionStreamActionKind.Finish : QuicConnectionStreamActionKind.Write,
            streamId,
            buffer.Length);
        completion.SuppressTerminalException = false;
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        if (cancellationToken.CanBeCanceled)
        {
            completion.RegisterCancellation(requestId, cancellationToken);
        }

        QuicConnectionStreamActionKind actionKind = finishWrites ? QuicConnectionStreamActionKind.Finish : QuicConnectionStreamActionKind.Write;
        bool posted = streamWriteDispatcher?.Invoke(requestId, actionKind, streamId, buffer)
            ?? TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
                clock.Ticks,
                requestId,
                actionKind,
                StreamId: streamId,
                StreamData: buffer));
        if (!posted)
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            completion.DisposeCancellationRegistration();
            ReturnStreamActionRequestCompletionSource(completion);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        return completion.UntypedTask;
    }

    private ValueTask<bool> WriteStreamAsyncCore(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        bool suppressTerminalException,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            if (suppressTerminalException)
            {
                return new ValueTask<bool>(false);
            }

            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (buffer.IsEmpty && !finishWrites)
        {
            return new ValueTask<bool>(true);
        }

        if (buffer.Length > MaximumStreamWriteChunkBytes)
        {
            return WriteStreamChunksAsync(streamId, buffer, finishWrites, suppressTerminalException, cancellationToken);
        }

        LogApplicationSend(
            $"app-tx api-write role={tlsState.Role} stream={streamId} length={buffer.Length} fin={finishWrites}.");

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        completion.ConfigureWrite(
            finishWrites ? QuicConnectionStreamActionKind.Finish : QuicConnectionStreamActionKind.Write,
            streamId,
            buffer.Length);
        completion.SuppressTerminalException = suppressTerminalException;
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            if (suppressTerminalException && (IsDisposed || terminalState is not null))
            {
                return new ValueTask<bool>(false);
            }

            throw new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        if (cancellationToken.CanBeCanceled)
        {
            completion.RegisterCancellation(requestId, cancellationToken);
        }

        QuicConnectionStreamActionKind actionKind = finishWrites ? QuicConnectionStreamActionKind.Finish : QuicConnectionStreamActionKind.Write;
        bool posted = streamWriteDispatcher?.Invoke(requestId, actionKind, streamId, buffer)
            ?? TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
                clock.Ticks,
                requestId,
                actionKind,
                StreamId: streamId,
                StreamData: buffer));
        if (!posted)
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            completion.DisposeCancellationRegistration();
            ReturnStreamActionRequestCompletionSource(completion);
            if (suppressTerminalException && (IsDisposed || terminalState is not null))
            {
                return new ValueTask<bool>(false);
            }

            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        return completion.Task;
    }

    private async ValueTask<bool> WriteStreamChunksAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        bool finishWrites,
        bool suppressTerminalException,
        CancellationToken cancellationToken)
    {
        while (!buffer.IsEmpty)
        {
            int chunkLength = Math.Min(buffer.Length, MaximumStreamWriteChunkBytes);
            bool finishChunk = finishWrites && chunkLength == buffer.Length;
            if (!await WriteStreamAsyncCore(streamId, buffer[..chunkLength], finishChunk, suppressTerminalException, cancellationToken).ConfigureAwait(false))
            {
                return false;
            }

            buffer = buffer[chunkLength..];
        }

        return true;
    }

    internal async ValueTask SendDatagramAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextDatagramSendRequestId);
        DatagramSendRequestCompletionSource completion = RentDatagramSendRequestCompletionSource();
        if (!pendingDatagramSendRequests.TryAdd(requestId, completion))
        {
            ReturnDatagramSendRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the DATAGRAM send request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.pendingDatagramSendRequests.TryRemove(requestId, out DatagramSendRequestCompletionSource? pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionDatagramSendRequestedEvent(
            clock.Ticks,
            requestId,
            datagram)))
        {
            if (pendingDatagramSendRequests.TryRemove(requestId, out DatagramSendRequestCompletionSource? removedCompletion))
            {
                ReturnDatagramSendRequestCompletionSource(removedCompletion);
            }
            else
            {
                await completion.Task.ConfigureAwait(false);
            }

            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the DATAGRAM send request.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    internal async ValueTask<ReadOnlyMemory<byte>> ReceiveDatagramAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            throw CreateTerminalException(terminalStateValue);
        }

        if (phase != QuicConnectionPhase.Active)
        {
            throw new InvalidOperationException(
                $"The connection is not established. Phase={phase} TerminalState={(terminalState.HasValue ? terminalState.Value.ToString() : "null")}");
        }

        if (tlsState.LocalTransportParameters?.MaxDatagramFrameSize is not > 0)
        {
            throw new InvalidOperationException("Local QUIC DATAGRAM receive support was not advertised.");
        }

        if (inboundDatagrams is null)
        {
            throw new InvalidOperationException("The inbound DATAGRAM receive queue is disabled.");
        }

        try
        {
            ReadOnlyMemory<byte> datagram = await inboundDatagrams.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (terminalState is QuicConnectionTerminalState completedTerminalState)
            {
                throw CreateTerminalException(completedTerminalState);
            }

            return datagram;
        }
        catch (ChannelClosedException) when (inboundDatagramQueueCompletionException is not null)
        {
            throw inboundDatagramQueueCompletionException;
        }
        catch (ChannelClosedException) when (terminalState is QuicConnectionTerminalState completedTerminalState)
        {
            throw CreateTerminalException(completedTerminalState);
        }
        catch (ChannelClosedException ex) when (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntime), ex);
        }
    }

    internal ValueTask CompleteStreamWritesAsync(
        ulong streamId,
        CancellationToken cancellationToken = default)
        => CompleteStreamWritesVoidAsyncCore(streamId, cancellationToken);

    internal ValueTask<bool> TryCompleteStreamWritesAsync(
        ulong streamId,
        CancellationToken cancellationToken = default)
        => CompleteStreamWritesAsyncCore(streamId, suppressTerminalException: true, cancellationToken);

    private ValueTask CompleteStreamWritesVoidAsyncCore(
        ulong streamId,
        CancellationToken cancellationToken)
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntime));
        }

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        completion.ConfigureWrite(
            QuicConnectionStreamActionKind.Finish,
            streamId,
            streamDataLength: 0);
        completion.SuppressTerminalException = false;
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        if (cancellationToken.CanBeCanceled)
        {
            completion.RegisterCancellation(requestId, cancellationToken);
        }

        bool posted = streamWriteDispatcher?.Invoke(
                requestId,
                QuicConnectionStreamActionKind.Finish,
                streamId,
                ReadOnlyMemory<byte>.Empty)
            ?? TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
                clock.Ticks,
                requestId,
                QuicConnectionStreamActionKind.Finish,
                StreamId: streamId));
        if (!posted)
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            completion.DisposeCancellationRegistration();
            ReturnStreamActionRequestCompletionSource(completion);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        return completion.UntypedTask;
    }

    private ValueTask<bool> CompleteStreamWritesAsyncCore(
        ulong streamId,
        bool suppressTerminalException,
        CancellationToken cancellationToken)
    {
        if (IsDisposed)
        {
            if (suppressTerminalException)
            {
                return new ValueTask<bool>(false);
            }

            throw new ObjectDisposedException(nameof(QuicConnectionRuntime));
        }

        if (terminalState is not null)
        {
            if (suppressTerminalException)
            {
                return new ValueTask<bool>(false);
            }

            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        completion.ConfigureWrite(
            QuicConnectionStreamActionKind.Finish,
            streamId,
            streamDataLength: 0);
        completion.SuppressTerminalException = suppressTerminalException;
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            if (suppressTerminalException && (IsDisposed || terminalState is not null))
            {
                return new ValueTask<bool>(false);
            }

            throw new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        if (cancellationToken.CanBeCanceled)
        {
            completion.RegisterCancellation(requestId, cancellationToken);
        }

        bool posted = streamWriteDispatcher?.Invoke(
                requestId,
                QuicConnectionStreamActionKind.Finish,
                streamId,
                ReadOnlyMemory<byte>.Empty)
            ?? TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
                clock.Ticks,
                requestId,
                QuicConnectionStreamActionKind.Finish,
                StreamId: streamId));
        if (!posted)
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            completion.DisposeCancellationRegistration();
            ReturnStreamActionRequestCompletionSource(completion);
            if (suppressTerminalException && (IsDisposed || terminalState is not null))
            {
                return new ValueTask<bool>(false);
            }

            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        return completion.Task;
    }

    internal async ValueTask AbortStreamWritesAsync(
        ulong streamId,
        ulong applicationErrorCode,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the stream reset request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.TryRemovePendingStreamActionRequest(requestId, out StreamActionRequestCompletionSource pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            requestId,
            QuicConnectionStreamActionKind.Reset,
            StreamId: streamId,
            ApplicationErrorCode: applicationErrorCode)))
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            ReturnStreamActionRequestCompletionSource(completion);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream reset request.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    internal async ValueTask AbortStreamReadsAsync(
        ulong streamId,
        ulong applicationErrorCode,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        StreamActionRequestCompletionSource completion = RentStreamActionRequestCompletionSource();
        if (!TryAddPendingStreamActionRequest(requestId, completion))
        {
            ReturnStreamActionRequestCompletionSource(completion);
            throw new InvalidOperationException("The connection runtime could not queue the stream stop-sending request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.TryRemovePendingStreamActionRequest(requestId, out StreamActionRequestCompletionSource pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            requestId,
            QuicConnectionStreamActionKind.StopSending,
            StreamId: streamId,
            ApplicationErrorCode: applicationErrorCode)))
        {
            TryRemovePendingStreamActionRequest(requestId, out _);
            ReturnStreamActionRequestCompletionSource(completion);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream stop-sending request.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the single logical consumer for the connection inbox until the inbox is completed or canceled.
    /// </summary>
    public Task RunAsync(
        Action<QuicConnectionTransitionResult>? transitionObserver = null,
        Action<QuicConnectionEffect>? effectObserver = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (Interlocked.CompareExchange(ref consumerStarted, 1, 0) != 0)
        {
            throw new InvalidOperationException("The connection runtime consumer can only be started once.");
        }

        Task processing = ConsumeInboxAsync(transitionObserver, effectObserver, cancellationToken);
        processingTask = processing;
        return processing;
    }

    public QuicConnectionTransitionResult Transition(QuicConnectionEvent connectionEvent)
    {
        return Transition(connectionEvent, clock.Ticks);
    }

    public QuicConnectionTransitionResult Transition(QuicConnectionEvent connectionEvent, long nowTicks)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);

        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;

        bool stateChanged = connectionEvent switch
        {
            QuicConnectionPeerHandshakeTranscriptCompletedEvent peerHandshakeTranscriptCompletedEvent
                => HandlePeerHandshakeTranscriptCompleted(peerHandshakeTranscriptCompletedEvent, nowTicks, ref effects),
            QuicConnectionRetryReceivedEvent retryReceivedEvent
                => HandleRetryReceived(retryReceivedEvent, nowTicks, ref effects),
            QuicConnectionHandshakeBootstrapRequestedEvent handshakeBootstrapRequestedEvent
                => HandleHandshakeBootstrapRequested(handshakeBootstrapRequestedEvent, nowTicks, ref effects),
            QuicConnectionTransportParametersCommittedEvent transportParametersCommittedEvent
                => ApplyTransportParameters(transportParametersCommittedEvent, nowTicks, ref effects),
            QuicConnectionTlsStateUpdatedEvent tlsStateUpdatedEvent
                => HandleTlsStateUpdated(tlsStateUpdatedEvent, nowTicks, ref effects),
            QuicConnectionCryptoFrameReceivedEvent cryptoFrameReceivedEvent
                => HandleCryptoFrameReceived(cryptoFrameReceivedEvent, nowTicks, ref effects),
            QuicConnectionStreamActionEvent streamActionEvent
                => HandleStreamAction(streamActionEvent, nowTicks, ref effects),
            QuicConnectionDatagramSendRequestedEvent datagramSendRequestedEvent
                => HandleDatagramSendRequested(datagramSendRequestedEvent, ref effects),
            QuicConnectionFlowControlCreditUpdatedEvent flowControlCreditUpdatedEvent
                => HandleFlowControlCreditUpdated(flowControlCreditUpdatedEvent, ref effects),
            QuicConnectionPacketReceivedEvent packetReceivedEvent
                => HandlePacketReceived(new QuicConnectionPacketReceivedContext(packetReceivedEvent), nowTicks, ref effects),
            QuicConnectionVersionNegotiationReceivedEvent versionNegotiationReceivedEvent
                => HandleVersionNegotiationReceived(versionNegotiationReceivedEvent, nowTicks, ref effects),
            QuicConnectionIcmpMaximumDatagramSizeReductionEvent icmpMaximumDatagramSizeReductionEvent
                => HandleIcmpMaximumDatagramSizeReduction(icmpMaximumDatagramSizeReductionEvent, nowTicks, ref effects),
            QuicConnectionPathValidationSucceededEvent pathValidationSucceededEvent
                => HandlePathValidationSucceeded(pathValidationSucceededEvent, nowTicks, ref effects),
            QuicConnectionPathValidationFailedEvent pathValidationFailedEvent
                => HandlePathValidationFailed(pathValidationFailedEvent, nowTicks, ref effects),
            QuicConnectionTimerExpiredEvent timerExpiredEvent
                => TryHandleTimerExpired(timerExpiredEvent, nowTicks, ref effects),
            QuicConnectionLocalCloseRequestedEvent localCloseRequestedEvent
                => HandleLocalCloseRequested(localCloseRequestedEvent, nowTicks, ref effects),
            QuicConnectionConnectionCloseFrameReceivedEvent connectionCloseFrameReceivedEvent
                => HandleConnectionCloseFrameReceived(connectionCloseFrameReceivedEvent, nowTicks, ref effects),
            QuicConnectionAcceptedStatelessResetEvent acceptedStatelessResetEvent
                => HandleAcceptedStatelessReset(acceptedStatelessResetEvent, nowTicks, ref effects),
            QuicConnectionConnectionIdIssuedEvent connectionIdIssuedEvent
                => HandleConnectionIdIssued(connectionIdIssuedEvent, ref effects),
            QuicConnectionConnectionIdRetiredEvent connectionIdRetiredEvent
                => HandleConnectionIdRetired(connectionIdRetiredEvent, ref effects),
            QuicConnectionConnectionIdAcknowledgedEvent connectionIdAcknowledgedEvent
                => HandleConnectionIdAcknowledged(connectionIdAcknowledgedEvent),
            _ => false,
        };

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            connectionEvent.Kind,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    internal QuicConnectionTransitionResult TransitionPacketReceived(
        QuicConnectionPacketReceivedContext packetReceived,
        long nowTicks)
    {
        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;
        bool stateChanged = HandlePacketReceived(packetReceived, nowTicks, ref effects);

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            QuicConnectionEventKind.PacketReceived,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    internal QuicConnectionTransitionResult TransitionStreamCapacityRelease(long nowTicks)
    {
        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;
        bool stateChanged = HandleReleaseCapacityStreamAction(ref effects);

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            QuicConnectionEventKind.StreamAction,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    internal QuicConnectionTransitionResult TransitionFlowControlCreditUpdate(long nowTicks)
    {
        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;
        bool stateChanged = HandleScheduledFlowControlCreditUpdated(ref effects);

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            QuicConnectionEventKind.FlowControlCreditUpdated,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    internal QuicConnectionTransitionResult TransitionStreamOpen(
        long requestId,
        QuicStreamType streamType,
        long nowTicks)
    {
        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;
        bool stateChanged = HandleOpenStreamAction(requestId, streamType, ref effects);

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            QuicConnectionEventKind.StreamAction,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    internal QuicConnectionTransitionResult TransitionStreamWrite(
        long requestId,
        QuicConnectionStreamActionKind actionKind,
        ulong streamId,
        ReadOnlyMemory<byte> streamData,
        long nowTicks)
    {
        QuicConnectionPhase previousPhase = phase;
        lastTransitionTicks = nowTicks;
        transitionSequence++;

        QuicConnectionEffectAccumulator effects = default;
        bool stateChanged = HandleWriteStreamAction(
            nowTicks,
            requestId,
            streamId,
            streamData,
            actionKind == QuicConnectionStreamActionKind.Finish,
            ref effects);

        return new QuicConnectionTransitionResult(
            transitionSequence,
            nowTicks,
            QuicConnectionEventKind.StreamAction,
            previousPhase,
            phase,
            stateChanged,
            effects);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

        try
        {
            Exception completionException = terminalState is QuicConnectionTerminalState terminalStateValue
                ? CreateTerminalException(terminalStateValue)
                : new ObjectDisposedException(nameof(QuicConnectionRuntime));

            CompletePendingStreamOperations(completionException);
            inbox.Writer.TryComplete();

            Task? processing = processingTask;
            if (processing is not null)
            {
                await processing.ConfigureAwait(false);
            }

            peerConnectionIdState.Clear();
            issuedConnectionIdState.Reset();
            ClearBufferedEstablishmentHandshakePackets();
        }
        finally
        {
            QuicMetrics.RecordConnectionClosed(tlsState.Role, terminalState);
        }
    }

    public void Dispose()
    {
        DisposeAsync().GetAwaiter().GetResult();
    }

    private async Task ConsumeInboxAsync(
        Action<QuicConnectionTransitionResult>? transitionObserver,
        Action<QuicConnectionEffect>? effectObserver,
        CancellationToken cancellationToken)
    {
        ChannelReader<QuicConnectionEvent> reader = inbox.Reader;
        CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.UnsafeRegister(static state =>
            {
                ChannelWriter<QuicConnectionEvent> writer = (ChannelWriter<QuicConnectionEvent>)state!;
                writer.TryComplete();
            }, inbox.Writer)
            : default;

        try
        {
            while (await reader.WaitToReadAsync().ConfigureAwait(false))
            {
                while (reader.TryRead(out QuicConnectionEvent? connectionEvent))
                {
                    try
                    {
                        QuicConnectionTransitionResult result = Transition(connectionEvent);
                        transitionObserver?.Invoke(result);

                        if (effectObserver is not null)
                        {
                            for (int index = 0; index < result.EffectCount; index++)
                            {
                                effectObserver(result.GetEffect(index));
                            }
                        }
                    }
                    finally
                    {
                        ReleaseConnectionEventResources(connectionEvent);
                    }
                }
            }
        }
        finally
        {
            await cancellationRegistration.DisposeAsync().ConfigureAwait(false);
            while (reader.TryRead(out QuicConnectionEvent? connectionEvent))
            {
                ReleaseConnectionEventResources(connectionEvent);
            }
        }
    }

    private static void ReleaseConnectionEventResources(QuicConnectionEvent connectionEvent)
    {
        if (connectionEvent is QuicConnectionPacketReceivedEvent packetReceivedEvent)
        {
            packetReceivedEvent.ReleaseOwnedDatagramBuffer();
        }
    }

    private bool TryPostEvent(QuicConnectionEvent connectionEvent)
    {
        ArgumentNullException.ThrowIfNull(connectionEvent);

        if (Volatile.Read(ref disposed) != 0)
        {
            return false;
        }

        return inbox.Writer.TryWrite(connectionEvent);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(QuicConnectionRuntime));
        }
    }

    internal Exception? GetStreamOperationException()
    {
        if (IsDisposed)
        {
            return new ObjectDisposedException(nameof(QuicConnectionRuntime));
        }

        return terminalState is QuicConnectionTerminalState terminalStateValue
            ? CreateTerminalException(terminalStateValue)
            : null;
    }
}
