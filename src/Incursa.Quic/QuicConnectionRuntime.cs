using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;

namespace Incursa.Quic;

/// <summary>
/// Owns the connection runtime shell, its single-consumer inbox, and the connection-owned transition path.
/// </summary>
internal sealed class QuicConnectionRuntime : IAsyncDisposable, IDisposable
{
    private const ulong TerminalLifetimePtoMultiplier = 3;
    private const ulong MicrosecondsPerSecond = 1_000_000UL;
    private const int DefaultCloseFrameOverheadBytes = 32;
    private const int PreferredAddressIPv4BytesLength = sizeof(uint);
    private const int PreferredAddressIPv6BytesLength = 16;
    private const ulong ApplicationSendDelayMicros = 1_000UL;
    private const int ApplicationSendDelayThresholdBytes = ApplicationMinimumProtectedPayloadLength;
    private const int HandshakeEgressChunkBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
    private const byte OutboundStreamControlFrameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
    private const int ApplicationMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private static readonly uint[] ClientSupportedVersions = [QuicVersionNegotiation.Version1];

    private readonly IMonotonicClock clock;
    private readonly QuicConnectionSendRuntime sendRuntime;
    private readonly QuicConnectionStreamRegistry streamRegistry;
    private readonly Channel<ulong> inboundStreamIds;
    private readonly Channel<QuicConnectionEvent> inbox;
    private readonly ConcurrentDictionary<long, TaskCompletionSource<ulong>> pendingStreamOpenRequests = new();
    private readonly ConcurrentDictionary<long, QuicStreamType> pendingStreamOpenTypes = new();
    private readonly ConcurrentDictionary<long, TaskCompletionSource<object?>> pendingStreamActionRequests = new();
    private readonly List<PendingApplicationSendRequest> pendingApplicationSendRequests = [];
    private readonly ConcurrentDictionary<ulong, ConcurrentDictionary<long, Action<QuicStreamNotification>>> streamObservers = new();
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> candidatePaths = [];
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> recentlyValidatedPaths = [];
    private readonly Dictionary<ulong, byte[]> statelessResetTokensByConnectionId = [];
    private readonly QuicConnectionPeerConnectionIdState peerConnectionIdState = new();
    private readonly long timeOriginTicks;
    private readonly QuicHandshakeFlowCoordinator handshakeFlowCoordinator;
    private readonly QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot;
    private readonly QuicDetachedResumptionTicketSnapshot? dormantDetachedResumptionTicketSnapshot;
    private readonly IQuicDiagnosticsSink diagnosticsSink;
    private readonly bool diagnosticsEnabled;
    private readonly QuicTransportTlsBridgeState tlsState;
    private readonly QuicTlsTransportBridgeDriver tlsBridgeDriver;
    private QuicInitialPacketProtection? initialPacketProtection;
    private QuicConnectionPathIdentity? bootstrapOutboundPathIdentity;
    private byte[]? initialBootstrapClientHelloBytes;
    private byte[]? ownedResumptionTicketBytes;
    private byte[]? ownedResumptionTicketNonce;
    private uint? ownedResumptionTicketLifetimeSeconds;
    private uint? ownedResumptionTicketAgeAdd;
    private uint? ownedResumptionTicketMaxEarlyDataSize;
    private QuicTransportParameters? ownedResumptionTicketPeerTransportParameters;
    private long? ownedResumptionTicketCapturedAtTicks;
    private byte[]? resumptionMasterSecret;
    private byte[]? retrySourceConnectionId;
    private byte[]? retryToken;
    private bool retryBootstrapPendingReplay;
    private bool zeroRttPacketSent;
    private bool handshakeDonePacketSent;
    private bool hasSuccessfullyProcessedAnotherPacket;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;
    private bool peerHandshakeTranscriptCompleted;
    private QuicConnectionTransportState transportFlags;
    private QuicConnectionActivePathRecord? activePath;
    private QuicConnectionTimerDeadlineState timerState = default;
    private QuicConnectionTerminalState? terminalState;
    private QuicIdleTimeoutState? idleTimeoutState;
    private QuicConnectionPhase phase = QuicConnectionPhase.Establishing;
    private ulong? localMaxIdleTimeoutMicros;
    private ulong? peerMaxIdleTimeoutMicros;
    private ulong currentProbeTimeoutMicros;
    private string? lastValidatedRemoteAddress;
    private QuicConnectionPathIdentity? preferredAddressOldPathIdentity;
    private long? terminalEndTicks;
    private long lastTransitionTicks;
    private ulong transitionSequence;
    private long nextStreamActionRequestId;
    private long nextStreamObserverId;
    private Exception? inboundStreamQueueCompletionException;
    private Func<QuicConnectionEvent, bool>? localApiEventDispatcher;
    private Action<int, int>? streamCapacityObserver;
    private long? pendingApplicationSendDelayDueTicks;

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
        bool enableRandomizedSpinBitSelection = false)
    {
        this.clock = clock ?? new MonotonicClock();
        timeOriginTicks = this.clock.Ticks;
        sendRuntime = new QuicConnectionSendRuntime();
        streamRegistry = new QuicConnectionStreamRegistry(bookkeeping);
        handshakeFlowCoordinator = new QuicHandshakeFlowCoordinator(enableRandomizedSpinBitSelection: enableRandomizedSpinBitSelection);
        this.clientCertificatePolicySnapshot = clientCertificatePolicySnapshot;
        this.diagnosticsSink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSink);
        diagnosticsEnabled = this.diagnosticsSink.IsEnabled;
        if (detachedResumptionTicketSnapshot is not null && tlsRole != QuicTlsRole.Client)
        {
            throw new ArgumentException("Detached resumption ticket snapshots are only supported for the client role.", nameof(detachedResumptionTicketSnapshot));
        }

        dormantDetachedResumptionTicketSnapshot = detachedResumptionTicketSnapshot;
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
            clientAuthenticationOptions);
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
        this.currentProbeTimeoutMicros = currentProbeTimeoutMicros;
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

    public QuicConnectionTransportState TransportFlags => transportFlags;

    public QuicConnectionActivePathRecord? ActivePath => activePath;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> CandidatePaths => candidatePaths;

    public IReadOnlyDictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> RecentlyValidatedPaths => recentlyValidatedPaths;

    public QuicConnectionTimerDeadlineState TimerState => timerState;

    public QuicConnectionTerminalState? TerminalState => terminalState;

    public QuicIdleTimeoutState? IdleTimeoutState => idleTimeoutState;

    public ulong? LocalMaxIdleTimeoutMicros => localMaxIdleTimeoutMicros;

    public ulong? PeerMaxIdleTimeoutMicros => peerMaxIdleTimeoutMicros;

    public ulong CurrentProbeTimeoutMicros => currentProbeTimeoutMicros;

    public string? LastValidatedRemoteAddress => lastValidatedRemoteAddress;

    internal ReadOnlyMemory<byte> CurrentPeerDestinationConnectionId
        => peerConnectionIdState.CurrentDestinationConnectionId.IsEmpty
            ? handshakeFlowCoordinator.DestinationConnectionId
            : peerConnectionIdState.CurrentDestinationConnectionId;

    public bool HasValidatedPath
    {
        get
        {
            if (activePath?.IsValidated ?? false)
            {
                return true;
            }

            if (recentlyValidatedPaths.Count > 0)
            {
                return true;
            }

            foreach (QuicConnectionCandidatePathRecord candidate in candidatePaths.Values)
            {
                if (candidate.Validation.IsValidated && !candidate.Validation.IsAbandoned)
                {
                    return true;
                }
            }

            return false;
        }
    }

    public QuicConnectionStreamRegistry StreamRegistry => streamRegistry;

    public int MaximumCandidatePaths { get; }

    public int MaximumRecentlyValidatedPaths { get; }

    public long LastTransitionTicks => lastTransitionTicks;

    public ulong TransitionSequence => transitionSequence;

    internal bool IsInboxConsumerRunning => Volatile.Read(ref consumerStarted) != 0;

    internal bool IsDisposed => Volatile.Read(ref disposed) != 0;

    internal IMonotonicClock Clock => clock;

    internal QuicConnectionSendRuntime SendRuntime => sendRuntime;

    internal QuicTransportTlsBridgeState TlsState => tlsState;

    internal ReadOnlyMemory<byte> OwnedResumptionTicketBytes => ownedResumptionTicketBytes ?? ReadOnlyMemory<byte>.Empty;

    internal bool HasOwnedResumptionTicket => ownedResumptionTicketBytes is not null;

    internal ReadOnlyMemory<byte> OwnedResumptionTicketNonce => ownedResumptionTicketNonce ?? ReadOnlyMemory<byte>.Empty;

    internal uint? OwnedResumptionTicketLifetimeSeconds => ownedResumptionTicketLifetimeSeconds;

    internal uint? OwnedResumptionTicketAgeAdd => ownedResumptionTicketAgeAdd;

    internal long? OwnedResumptionTicketCapturedAtTicks => ownedResumptionTicketCapturedAtTicks;

    internal ReadOnlyMemory<byte> ResumptionMasterSecret => resumptionMasterSecret ?? tlsState.ResumptionMasterSecret;

    internal bool HasResumptionMasterSecret => resumptionMasterSecret is not null || tlsState.HasResumptionMasterSecret;

    internal bool IsEarlyDataAdmissionOpen => false;

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

    internal bool TryConfigureInitialPacketProtection(ReadOnlySpan<byte> clientInitialDestinationConnectionId)
    {
        if (initialPacketProtection is not null)
        {
            return true;
        }

        if (!QuicInitialPacketProtection.TryCreate(
            tlsState.Role,
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
            ownedResumptionTicketBytes,
            ownedResumptionTicketNonce,
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

        _ = TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            RequestId: 0,
            QuicConnectionStreamActionKind.ReleaseCapacity,
            StreamId: streamId));
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

        _ = TryPostLocalApiEvent(new QuicConnectionFlowControlCreditUpdatedEvent(
            clock.Ticks,
            maxDataFrame,
            maxStreamDataFrame));
    }

    internal long RegisterStreamObserver(ulong streamId, Action<QuicStreamNotification> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        long observerId = Interlocked.Increment(ref nextStreamObserverId);
        ConcurrentDictionary<long, Action<QuicStreamNotification>> observers = streamObservers.GetOrAdd(
            streamId,
            static _ => new ConcurrentDictionary<long, Action<QuicStreamNotification>>());

        if (!observers.TryAdd(observerId, observer))
        {
            throw new InvalidOperationException("The connection runtime could not register the stream observer.");
        }

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            observer(new QuicStreamNotification(
                QuicStreamNotificationKind.ConnectionTerminated,
                CreateTerminalException(terminalStateValue)));
        }
        else
        {
            if (streamRegistry.Bookkeeping.TryGetReceiveAbortErrorCode(streamId, out ulong receiveAbortErrorCode))
            {
                observer(new QuicStreamNotification(
                    QuicStreamNotificationKind.ReadAborted,
                    CreateStreamReadAbortedException(receiveAbortErrorCode)));
            }

            if (streamRegistry.Bookkeeping.TryGetSendAbortErrorCode(streamId, out ulong sendAbortErrorCode))
            {
                observer(new QuicStreamNotification(
                    QuicStreamNotificationKind.WriteAborted,
                    CreateStreamWriteAbortedException(sendAbortErrorCode)));
            }
        }

        return observerId;
    }

    internal void UnregisterStreamObserver(ulong streamId, long observerId)
    {
        if (!streamObservers.TryGetValue(streamId, out ConcurrentDictionary<long, Action<QuicStreamNotification>>? observers))
        {
            return;
        }

        observers.TryRemove(observerId, out _);
        if (observers.IsEmpty)
        {
            streamObservers.TryRemove(streamId, out _);
        }
    }

    internal async ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            throw CreateTerminalException(terminalStateValue);
        }

        if (phase != QuicConnectionPhase.Active)
        {
            throw new InvalidOperationException("The connection is not established.");
        }

        try
        {
            ulong streamId = await inboundStreamIds.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
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

    internal async ValueTask<QuicStream> OpenOutboundStreamAsync(
        QuicStreamType streamType,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            throw CreateTerminalException(terminalStateValue);
        }

        if (phase != QuicConnectionPhase.Active || activePath is null)
        {
            throw new InvalidOperationException("The connection is not established.");
        }

        if (streamType is not QuicStreamType.Unidirectional and not QuicStreamType.Bidirectional)
        {
            throw new ArgumentOutOfRangeException(nameof(streamType));
        }

        if (!tlsState.OneRttKeysAvailable
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            throw new InvalidOperationException("The connection is not ready to open application streams.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        TaskCompletionSource<ulong> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingStreamOpenRequests.TryAdd(requestId, completion)
            || !pendingStreamOpenTypes.TryAdd(requestId, streamType))
        {
            pendingStreamOpenRequests.TryRemove(requestId, out _);
            pendingStreamOpenTypes.TryRemove(requestId, out _);
            throw new InvalidOperationException("The connection runtime could not queue the stream open request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.TryRemovePendingStreamOpenRequest(requestId, out TaskCompletionSource<ulong>? pendingCompletion))
                {
                    pendingCompletion!.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            requestId,
            QuicConnectionStreamActionKind.Open,
            StreamType: streamType)))
        {
            TryRemovePendingStreamOpenRequest(requestId, out _);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream open request.");
        }

        ulong streamId = await completion.Task.ConfigureAwait(false);

        if (!streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out _))
        {
            throw new InvalidOperationException("The stream open completed without a committed stream state.");
        }

        return new QuicStream(streamRegistry.Bookkeeping, streamId, this);
    }

    internal async ValueTask WriteStreamAsync(
        ulong streamId,
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        if (buffer.IsEmpty)
        {
            return;
        }

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        TaskCompletionSource<object?> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingStreamActionRequests.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            requestId,
            QuicConnectionStreamActionKind.Write,
            StreamId: streamId,
            StreamData: buffer.ToArray())))
        {
            pendingStreamActionRequests.TryRemove(requestId, out _);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream write request.");
        }

        await completion.Task.ConfigureAwait(false);
    }

    internal async ValueTask CompleteStreamWritesAsync(
        ulong streamId,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (terminalState is not null)
        {
            throw CreateTerminalException(terminalState.Value);
        }

        cancellationToken.ThrowIfCancellationRequested();

        long requestId = Interlocked.Increment(ref nextStreamActionRequestId);
        TaskCompletionSource<object?> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingStreamActionRequests.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? pendingCompletion))
                {
                    pendingCompletion.TrySetCanceled(token);
                }
            }, (this, requestId, cancellationToken))
            : default;

        if (!TryPostLocalApiEvent(new QuicConnectionStreamActionEvent(
            clock.Ticks,
            requestId,
            QuicConnectionStreamActionKind.Finish,
            StreamId: streamId)))
        {
            pendingStreamActionRequests.TryRemove(requestId, out _);
            throw IsDisposed
                ? new ObjectDisposedException(nameof(QuicConnectionRuntime))
                : new InvalidOperationException("The connection runtime could not queue the stream finish request.");
        }

        await completion.Task.ConfigureAwait(false);
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
        TaskCompletionSource<object?> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingStreamActionRequests.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("The connection runtime could not queue the stream reset request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? pendingCompletion))
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
            pendingStreamActionRequests.TryRemove(requestId, out _);
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
        TaskCompletionSource<object?> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!pendingStreamActionRequests.TryAdd(requestId, completion))
        {
            throw new InvalidOperationException("The connection runtime could not queue the stream stop-sending request.");
        }

        using CancellationTokenRegistration cancellationRegistration = cancellationToken.CanBeCanceled
            ? cancellationToken.Register(static state =>
            {
                (QuicConnectionRuntime runtime, long requestId, CancellationToken token) =
                    ((QuicConnectionRuntime, long, CancellationToken))state!;

                if (runtime.pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? pendingCompletion))
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
            pendingStreamActionRequests.TryRemove(requestId, out _);
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

        List<QuicConnectionEffect>? effects = null;

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
            QuicConnectionFlowControlCreditUpdatedEvent flowControlCreditUpdatedEvent
                => HandleFlowControlCreditUpdated(flowControlCreditUpdatedEvent, ref effects),
            QuicConnectionPacketReceivedEvent packetReceivedEvent
                => HandlePacketReceived(packetReceivedEvent, nowTicks, ref effects),
            QuicConnectionVersionNegotiationReceivedEvent versionNegotiationReceivedEvent
                => HandleVersionNegotiationReceived(versionNegotiationReceivedEvent, nowTicks, ref effects),
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
            effects?.ToArray() ?? Array.Empty<QuicConnectionEffect>());
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0)
        {
            return;
        }

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

        try
        {
            while (await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (reader.TryRead(out QuicConnectionEvent? connectionEvent))
                {
                    QuicConnectionTransitionResult result = Transition(connectionEvent);
                    transitionObserver?.Invoke(result);

                    if (effectObserver is not null)
                    {
                        foreach (QuicConnectionEffect effect in result.Effects)
                        {
                            effectObserver(effect);
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The owner requested a stop; queued events are left to the caller's shutdown policy.
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

    private bool HandlePeerHandshakeTranscriptCompleted(
        QuicConnectionPeerHandshakeTranscriptCompletedEvent peerHandshakeTranscriptCompletedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = peerHandshakeTranscriptCompletedEvent;

        bool stateChanged = tlsState.TryMarkPeerHandshakeTranscriptCompleted();

        if (!peerHandshakeTranscriptCompleted)
        {
            peerHandshakeTranscriptCompleted = true;
            stateChanged = true;

            if (phase == QuicConnectionPhase.Establishing)
            {
                phase = QuicConnectionPhase.Active;
            }

            if (TryPromoteValidatedCandidatePath(nowTicks, ref effects))
            {
                stateChanged = true;
            }

            stateChanged |= TryFlushHandshakeDonePacket(ref effects);
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return stateChanged;
    }

    private bool HandleHandshakeBootstrapRequested(
        QuicConnectionHandshakeBootstrapRequestedEvent handshakeBootstrapRequestedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || tlsState.LocalTransportParameters is not null)
        {
            return false;
        }

        QuicTransportParameters? localTransportParameters = handshakeBootstrapRequestedEvent.LocalTransportParameters;
        if (localTransportParameters is null)
        {
            return false;
        }

        IReadOnlyList<QuicTlsStateUpdate> updates = tlsBridgeDriver.StartHandshake(
            localTransportParameters,
            dormantDetachedResumptionTicketSnapshot,
            nowTicks);
        if (updates.Count == 0)
        {
            return false;
        }

        bool stateChanged = true;
        foreach (QuicTlsStateUpdate update in updates)
        {
            stateChanged |= HandleTlsStateUpdated(
                new QuicConnectionTlsStateUpdatedEvent(handshakeBootstrapRequestedEvent.ObservedAtTicks, update),
                nowTicks,
                ref effects);
        }

        IReadOnlyList<QuicTlsStateUpdate> replayedHandshakeUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.Handshake);
        if (replayedHandshakeUpdates.Count > 0)
        {
            stateChanged = true;

            foreach (QuicTlsStateUpdate replayedHandshakeUpdate in replayedHandshakeUpdates)
            {
                stateChanged |= HandleTlsStateUpdated(
                    new QuicConnectionTlsStateUpdatedEvent(handshakeBootstrapRequestedEvent.ObservedAtTicks, replayedHandshakeUpdate),
                    nowTicks,
                    ref effects);
            }
        }

        return stateChanged;
    }

    private bool HandleRetryReceived(
        QuicConnectionRetryReceivedEvent retryReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;
        _ = effects;

        if (phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || retryBootstrapPendingReplay
            || retrySourceConnectionId is not null
            || retryReceivedEvent.RetrySourceConnectionId.IsEmpty
            || retryReceivedEvent.RetryToken.IsEmpty)
        {
            return false;
        }

        retrySourceConnectionId = retryReceivedEvent.RetrySourceConnectionId.ToArray();
        retryToken = retryReceivedEvent.RetryToken.ToArray();
        retryBootstrapPendingReplay = true;
        hasSuccessfullyProcessedAnotherPacket = true;

        bool stateChanged = true;
        stateChanged |= TrySetHandshakeDestinationConnectionId(retryReceivedEvent.RetrySourceConnectionId.Span);
        EmitDiagnostic(ref effects, QuicDiagnostics.RetryReceived(retryReceivedEvent.Datagram.Span));
        stateChanged |= TryFlushInitialPackets(ref effects);
        return stateChanged;
    }

    private bool HandleVersionNegotiationReceived(
        QuicConnectionVersionNegotiationReceivedEvent versionNegotiationReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;

        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal)
        {
            return false;
        }

        if (!QuicPacketParser.TryParseVersionNegotiation(
                versionNegotiationReceivedEvent.Datagram.Span,
                out QuicVersionNegotiationPacket versionNegotiationPacket))
        {
            return false;
        }

        if (!QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
                versionNegotiationPacket,
                QuicVersionNegotiation.Version1,
                ClientSupportedVersions,
                hasSuccessfullyProcessedAnotherPacket))
        {
            return false;
        }

        EmitDiagnostic(ref effects, QuicDiagnostics.VersionNegotiationReceived(versionNegotiationReceivedEvent.Datagram.Span));
        return DiscardConnection(
            versionNegotiationReceivedEvent.ObservedAtTicks,
            QuicConnectionCloseOrigin.VersionNegotiation,
            default,
            ref effects);
    }

    private bool HandleTlsStateUpdated(
        QuicConnectionTlsStateUpdatedEvent tlsStateUpdatedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = tlsBridgeDriver.TryApply(tlsStateUpdatedEvent.Update);

        switch (tlsStateUpdatedEvent.Update.Kind)
        {
            case QuicTlsUpdateKind.LocalTransportParametersReady:
                stateChanged |= TryCommitLocalTransportParametersFromTlsBridgeState(nowTicks, ref effects);
                break;

            case QuicTlsUpdateKind.PeerCertificatePolicyAccepted:
            case QuicTlsUpdateKind.PeerFinishedVerified:
                stateChanged |= TryCommitPeerTransportParametersFromTlsBridgeDriver(nowTicks, ref effects);
                if (tlsStateUpdatedEvent.Update.Kind == QuicTlsUpdateKind.PeerFinishedVerified)
                {
                    stateChanged |= TryCaptureResumptionMasterSecret();
                }
                break;

            case QuicTlsUpdateKind.PeerHandshakeTranscriptCompleted:
                stateChanged |= TryCommitPeerTransportParametersFromTlsBridgeDriver(nowTicks, ref effects);
                if (tlsState.PeerHandshakeTranscriptCompleted)
                {
                    stateChanged |= HandlePeerHandshakeTranscriptCompleted(
                        new QuicConnectionPeerHandshakeTranscriptCompletedEvent(tlsStateUpdatedEvent.ObservedAtTicks),
                        nowTicks,
                        ref effects);
                }
                break;

            case QuicTlsUpdateKind.PeerTransportParametersCommitted:
                stateChanged |= TryCommitPeerTransportParametersFromTlsBridgeState(nowTicks, ref effects);
                break;

            case QuicTlsUpdateKind.KeysDiscarded:
                stateChanged |= HandleTlsKeyDiscard(tlsStateUpdatedEvent.Update.EncryptionLevel!.Value, ref effects);
                break;

            case QuicTlsUpdateKind.FatalAlert:
                stateChanged |= HandleFatalTlsSignal(
                    tlsStateUpdatedEvent.ObservedAtTicks,
                    tlsState.FatalAlertCode ?? QuicTransportErrorCode.ProtocolViolation,
                    tlsState.FatalAlertDescription,
                    ref effects);
                break;

            case QuicTlsUpdateKind.ProhibitedKeyUpdateViolation:
                stateChanged |= HandleFatalTlsSignal(
                    tlsStateUpdatedEvent.ObservedAtTicks,
                    QuicTransportErrorCode.KeyUpdateError,
                    "TLS KeyUpdate was prohibited.",
                    ref effects);
                break;

            case QuicTlsUpdateKind.KeysAvailable:
            case QuicTlsUpdateKind.CryptoDataAvailable:
            case QuicTlsUpdateKind.PacketProtectionMaterialAvailable:
            case QuicTlsUpdateKind.HandshakeOpenPacketProtectionMaterialAvailable:
            case QuicTlsUpdateKind.HandshakeProtectPacketProtectionMaterialAvailable:
            case QuicTlsUpdateKind.ResumptionMasterSecretAvailable:
            case QuicTlsUpdateKind.PostHandshakeTicketAvailable:
                if (tlsStateUpdatedEvent.Update.Kind == QuicTlsUpdateKind.CryptoDataAvailable
                    && tlsState.Role == QuicTlsRole.Client
                    && initialBootstrapClientHelloBytes is null
                    && !tlsStateUpdatedEvent.Update.CryptoData.IsEmpty)
                {
                    initialBootstrapClientHelloBytes = tlsStateUpdatedEvent.Update.CryptoData.ToArray();
                }

                if (tlsStateUpdatedEvent.Update.Kind == QuicTlsUpdateKind.ResumptionMasterSecretAvailable)
                {
                    stateChanged |= TryCaptureResumptionMasterSecret();
                }

                if (tlsStateUpdatedEvent.Update.Kind == QuicTlsUpdateKind.PostHandshakeTicketAvailable)
                {
                    stateChanged |= TryCaptureOwnedResumptionTicketSnapshot(nowTicks);
                }

                stateChanged |= TryFlushInitialPackets(ref effects);
                stateChanged |= TryFlushZeroRttPackets(ref effects);
                stateChanged |= TryFlushHandshakePackets(ref effects);
                stateChanged |= TryFlushHandshakeDonePacket(ref effects);
                break;
        }

        stateChanged |= TryCaptureResumptionMasterSecret();
        return stateChanged;
    }

    private bool HandleCryptoFrameReceived(
        QuicConnectionCryptoFrameReceivedEvent cryptoFrameReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;
        _ = effects;

        return tlsBridgeDriver.TryBufferIncomingCryptoData(
            cryptoFrameReceivedEvent.EncryptionLevel,
            cryptoFrameReceivedEvent.Offset,
            cryptoFrameReceivedEvent.CryptoData,
            out _);
    }

    private bool HandleStreamAction(
        QuicConnectionStreamActionEvent streamActionEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return streamActionEvent.ActionKind switch
        {
            QuicConnectionStreamActionKind.Open
                when streamActionEvent.StreamType is QuicStreamType streamType
                => HandleOpenStreamAction(streamActionEvent.RequestId, streamType, ref effects),
            QuicConnectionStreamActionKind.Write
                when streamActionEvent.StreamId.HasValue
                => HandleWriteStreamAction(
                    nowTicks,
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.StreamData,
                    finishWrites: false,
                    ref effects),
            QuicConnectionStreamActionKind.Finish
                when streamActionEvent.StreamId.HasValue
                => HandleWriteStreamAction(
                    nowTicks,
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    ReadOnlyMemory<byte>.Empty,
                    finishWrites: true,
                    ref effects),
            QuicConnectionStreamActionKind.Reset
                when streamActionEvent.StreamId.HasValue && streamActionEvent.ApplicationErrorCode.HasValue
                => HandleResetStreamAction(
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.ApplicationErrorCode.Value,
                    ref effects),
            QuicConnectionStreamActionKind.StopSending
                when streamActionEvent.StreamId.HasValue && streamActionEvent.ApplicationErrorCode.HasValue
                => HandleStopSendingStreamAction(
                    streamActionEvent.RequestId,
                    streamActionEvent.StreamId.Value,
                    streamActionEvent.ApplicationErrorCode.Value,
                    ref effects),
            QuicConnectionStreamActionKind.ReleaseCapacity
                when streamActionEvent.StreamId.HasValue
                => HandleReleaseCapacityStreamAction(
                    streamActionEvent.StreamId.Value,
                    ref effects),
            _ => false,
        };
    }

    private bool HandleOpenStreamAction(
        long requestId,
        QuicStreamType streamType,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryProcessPendingStreamOpenRequest(requestId, streamType, ref effects, out bool stillPending))
        {
            return false;
        }

        _ = stillPending;
        return true;
    }

    private bool TryRetryPendingStreamOpenRequests(
        bool bidirectional,
        ref List<QuicConnectionEffect>? effects)
    {
        if (pendingStreamOpenTypes.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        KeyValuePair<long, QuicStreamType>[] pendingRequests = pendingStreamOpenTypes.ToArray();
        Array.Sort(pendingRequests, static (left, right) => left.Key.CompareTo(right.Key));

        foreach (KeyValuePair<long, QuicStreamType> pendingRequest in pendingRequests)
        {
            if ((pendingRequest.Value == QuicStreamType.Bidirectional) != bidirectional)
            {
                continue;
            }

            if (!TryProcessPendingStreamOpenRequest(
                pendingRequest.Key,
                pendingRequest.Value,
                ref effects,
                out bool stillPending))
            {
                continue;
            }

            if (stillPending)
            {
                return stateChanged;
            }

            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryProcessPendingStreamOpenRequest(
        long requestId,
        QuicStreamType streamType,
        ref List<QuicConnectionEffect>? effects,
        out bool stillPending)
    {
        stillPending = false;

        if (!pendingStreamOpenRequests.TryGetValue(requestId, out TaskCompletionSource<ulong>? completion)
            || !pendingStreamOpenTypes.TryGetValue(requestId, out QuicStreamType trackedStreamType)
            || trackedStreamType != streamType)
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            if (TryRemovePendingStreamOpenRequest(requestId, out TaskCompletionSource<ulong>? removedCompletion))
            {
                removedCompletion!.TrySetException(exception!);
            }
            else
            {
                completion.TrySetException(exception!);
            }

            return true;
        }

        bool bidirectional = streamType == QuicStreamType.Bidirectional;
        if (!streamRegistry.Bookkeeping.TryPeekLocalStream(bidirectional, out QuicStreamId streamId, out _))
        {
            stillPending = true;
            return true;
        }

        if (!TryRemovePendingStreamOpenRequest(requestId, out TaskCompletionSource<ulong>? openCompletion))
        {
            return false;
        }

        if (!TryBuildOutboundStreamPayload(streamId.Value, 0, ReadOnlySpan<byte>.Empty, fin: false, out byte[] streamPayload))
        {
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not build the stream open payload."));
            return true;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream open packet.",
            "The connection cannot send the stream open packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? payloadException))
        {
            openCompletion!.TrySetException(payloadException!);
            return true;
        }

        if (!streamRegistry.Bookkeeping.TryOpenLocalStream(bidirectional, out QuicStreamId committedStreamId, out QuicStreamsBlockedFrame committedBlockedFrame))
        {
            _ = committedBlockedFrame;
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime could not commit the stream open."));
            return true;
        }

        if (committedStreamId.Value != streamId.Value)
        {
            openCompletion!.TrySetException(new InvalidOperationException("The connection runtime committed an unexpected outbound stream identifier."));
            return true;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        openCompletion!.TrySetResult(committedStreamId.Value);
        return true;
    }

    private bool HandleWriteStreamAction(
        long nowTicks,
        long requestId,
        ulong streamId,
        ReadOnlyMemory<byte> streamData,
        bool finishWrites,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot))
        {
            completion.TrySetException(new InvalidOperationException("The stream is not available on this connection."));
            return false;
        }

        if (snapshot.SendState == QuicStreamSendState.None)
        {
            completion.TrySetException(new InvalidOperationException("This stream does not have a writable side."));
            return false;
        }

        if (snapshot.SendState is QuicStreamSendState.DataSent or QuicStreamSendState.ResetSent)
        {
            completion.TrySetException(new InvalidOperationException("The writable side is already completed."));
            return false;
        }

        ulong writeOffset = snapshot.UniqueBytesSent;
        if (!streamRegistry.Bookkeeping.TryReserveSendCapacity(
            streamId,
            writeOffset,
            streamData.Length,
            finishWrites,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode))
        {
            if (errorCode != default)
            {
                completion.TrySetException(new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)errorCode,
                    "The stream write could not be committed."));
            }
            else if (dataBlockedFrame.MaximumData != 0 || streamDataBlockedFrame.MaximumStreamData != 0)
            {
                _ = TryEmitFlowControlBlockedSignal(dataBlockedFrame, streamDataBlockedFrame, ref effects);
                completion.TrySetException(new NotSupportedException(
                    "Writes that wait for additional flow-control credit are not supported by this slice."));
            }
            else
            {
                completion.TrySetException(new InvalidOperationException("The stream write could not be committed."));
            }

            return false;
        }

        if (!TryBuildOutboundStreamPayload(streamId, writeOffset, streamData.Span, finishWrites, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream write payload."));
            return false;
        }

        if (ShouldDelayApplicationSend(streamData.Span))
        {
            QueuePendingApplicationSend(streamId, streamPayload, nowTicks, ref effects);
            completion.TrySetResult(null);
            return true;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream write packet.",
            "The connection cannot send the stream write packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        if (finishWrites)
        {
            TryReleasePeerStreamCapacity(streamId, ref effects);
        }

        completion.TrySetResult(null);
        return true;
    }

    private bool ShouldDelayApplicationSend(ReadOnlySpan<byte> streamData)
    {
        return (activePath?.AmplificationState.IsAddressValidated ?? false)
            && streamData.Length > 0
            && (pendingApplicationSendRequests.Count > 0
                || streamData.Length < ApplicationSendDelayThresholdBytes);
    }

    private void QueuePendingApplicationSend(
        ulong streamId,
        byte[] streamPayload,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        pendingApplicationSendRequests.Add(new PendingApplicationSendRequest(streamId, streamPayload));

        if (pendingApplicationSendRequests.Count == 1)
        {
            pendingApplicationSendDelayDueTicks = SaturatingAdd(
                nowTicks,
                ConvertMicrosToTicks(ApplicationSendDelayMicros));
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
    }

    private bool FlushPendingApplicationSends(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;

        if (pendingApplicationSendRequests.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            return false;
        }

        PendingApplicationSendRequest[] queuedWrites = pendingApplicationSendRequests.ToArray();
        pendingApplicationSendRequests.Clear();
        pendingApplicationSendDelayDueTicks = null;

        int combinedPayloadLength = 0;
        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            combinedPayloadLength = checked(combinedPayloadLength + queuedWrite.StreamPayload.Length);
        }

        byte[] combinedPayload = new byte[combinedPayloadLength];
        int copyOffset = 0;
        foreach (PendingApplicationSendRequest queuedWrite in queuedWrites)
        {
            queuedWrite.StreamPayload.CopyTo(combinedPayload.AsSpan(copyOffset));
            copyOffset += queuedWrite.StreamPayload.Length;
        }

        if (!TryProtectAndAccountApplicationPayload(
            combinedPayload,
            "The connection runtime could not protect the queued stream write packet.",
            "The connection cannot send the queued stream write packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private void TryRemoveQueuedApplicationSendsForStream(ulong streamId, ref List<QuicConnectionEffect>? effects)
    {
        if (pendingApplicationSendRequests.Count == 0)
        {
            return;
        }

        bool removedAny = false;
        for (int index = pendingApplicationSendRequests.Count - 1; index >= 0; index--)
        {
            if (pendingApplicationSendRequests[index].StreamId != streamId)
            {
                continue;
            }

            pendingApplicationSendRequests.RemoveAt(index);
            removedAny = true;
        }

        if (removedAny && pendingApplicationSendRequests.Count == 0)
        {
            pendingApplicationSendDelayDueTicks = null;
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }
    }

    private bool TryEmitFlowControlBlockedSignal(
        QuicDataBlockedFrame dataBlockedFrame,
        QuicStreamDataBlockedFrame streamDataBlockedFrame,
        ref List<QuicConnectionEffect>? effects)
    {
        if (sendRuntime.HasAckElicitingPacketsInFlight || sendRuntime.PendingRetransmissionCount > 0)
        {
            return false;
        }

        if (dataBlockedFrame.MaximumData != 0)
        {
            return TrySendFlowControlBlockedSignal(
                dataBlockedFrame,
                "The connection runtime could not protect the data-blocked packet.",
                "The connection cannot send the data-blocked packet.",
                ref effects);
        }

        if (streamDataBlockedFrame.MaximumStreamData != 0)
        {
            return TrySendFlowControlBlockedSignal(
                streamDataBlockedFrame,
                "The connection runtime could not protect the stream-data-blocked packet.",
                "The connection cannot send the stream-data-blocked packet.",
                ref effects);
        }

        return false;
    }

    private bool TryEmitFlowControlCreditUpdate(
        QuicMaxDataFrame? maxDataFrame,
        QuicMaxStreamDataFrame? maxStreamDataFrame,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = false;

        if (maxDataFrame.HasValue)
        {
            stateChanged |= TrySendFlowControlCreditUpdate(
                maxDataFrame.Value,
                "The connection runtime could not protect the MAX_DATA packet.",
                "The connection cannot send the MAX_DATA packet.",
                ref effects);
        }

        if (maxStreamDataFrame.HasValue)
        {
            stateChanged |= TrySendFlowControlCreditUpdate(
                maxStreamDataFrame.Value,
                "The connection runtime could not protect the MAX_STREAM_DATA packet.",
                "The connection cannot send the MAX_STREAM_DATA packet.",
                ref effects);
        }

        return stateChanged;
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxDataFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundMaxDataPayload(frame, out byte[] payload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TrySendFlowControlCreditUpdate(
        QuicMaxStreamDataFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundMaxStreamDataPayload(frame, out byte[] payload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            payload,
            protectFailureMessage,
            amplificationFailureMessage,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TrySendFlowControlBlockedSignal(
        QuicDataBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundDataBlockedPayload(frame, out byte[] blockedPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            blockedPayload,
            protectFailureMessage,
            amplificationFailureMessage,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TrySendFlowControlBlockedSignal(
        QuicStreamDataBlockedFrame frame,
        string protectFailureMessage,
        string amplificationFailureMessage,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryBuildOutboundStreamDataBlockedPayload(frame, out byte[] blockedPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            blockedPayload,
            protectFailureMessage,
            amplificationFailureMessage,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool HandleResetStreamAction(
        long requestId,
        ulong streamId,
        ulong applicationErrorCode,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryAbortLocalStreamWrites(
            streamId,
            out ulong finalSize,
            out QuicTransportErrorCode errorCode))
        {
            completion.TrySetException(errorCode != default
                ? new QuicException(
                    QuicError.TransportError,
                    null,
                    (long)errorCode,
                    "The stream reset could not be committed.")
                : new InvalidOperationException("The writable side is already completed."));
            return false;
        }

        TryRemoveQueuedApplicationSendsForStream(streamId, ref effects);

        if (!TryBuildOutboundResetPayload(streamId, applicationErrorCode, finalSize, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream reset payload."));
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream reset packet.",
            "The connection cannot send the stream reset packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        TryReleasePeerStreamCapacity(streamId, ref effects);
        NotifyStreamObservers(
            streamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.WriteAborted,
                CreateLocalOperationAbortedException("The local write side was aborted.")));

        completion.TrySetResult(null);
        return true;
    }

    private bool HandleStopSendingStreamAction(
        long requestId,
        ulong streamId,
        ulong applicationErrorCode,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!pendingStreamActionRequests.TryRemove(requestId, out TaskCompletionSource<object?>? completion))
        {
            return false;
        }

        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        if (!TryBuildOutboundStopSendingPayload(streamId, applicationErrorCode, out byte[] streamPayload))
        {
            completion.TrySetException(new InvalidOperationException("The connection runtime could not build the stream stop-sending payload."));
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream stop-sending packet.",
            "The connection cannot send the stream stop-sending packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out exception))
        {
            completion.TrySetException(exception!);
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        TryReleasePeerStreamCapacity(streamId, ref effects);
        NotifyStreamObservers(
            streamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.ReadAborted,
                CreateLocalOperationAbortedException("The local read side was aborted.")));

        completion.TrySetResult(null);
        return true;
    }

    private bool HandleReleaseCapacityStreamAction(
        ulong streamId,
        ref List<QuicConnectionEffect>? effects)
    {
        return TryReleasePeerStreamCapacity(streamId, ref effects);
    }

    private bool HandleFlowControlCreditUpdated(
        QuicConnectionFlowControlCreditUpdatedEvent flowControlCreditUpdatedEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        return TryEmitFlowControlCreditUpdate(
            flowControlCreditUpdatedEvent.MaxDataFrame,
            flowControlCreditUpdatedEvent.MaxStreamDataFrame,
            ref effects);
    }

    private bool TryHandleInitialPacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketReceived(packetReceivedEvent.PathIdentity, packetReceivedEvent.Datagram.Span));
        }

        ReadOnlySpan<byte> datagram = packetReceivedEvent.Datagram.Span;
        if (!QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Initial
            || initialPacketProtection is null
            || !handshakeFlowCoordinator.TryOpenInitialPacket(
                datagram,
                initialPacketProtection,
                requireZeroTokenLength: tlsState.Role == QuicTlsRole.Client,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketOpenFailed(packetReceivedEvent.PathIdentity, datagram));
            }

            return false;
        }

        if (tlsState.Role == QuicTlsRole.Client
            && QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out _,
                out _,
                out ReadOnlySpan<byte> initialSourceConnectionId,
                out _))
        {
            _ = TrySetHandshakeDestinationConnectionId(initialSourceConnectionId);
        }

        bool processed = TryProcessHandshakePacketPayload(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            QuicTlsEncryptionLevel.Initial,
            nowTicks,
            ref effects);

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketProcessingResult(processed));
        }

        return processed;
    }

    private bool TryHandleHandshakePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        ReadOnlySpan<byte> datagram = packetReceivedEvent.Datagram.Span;
        if (!QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Handshake)
        {
            return false;
        }

        if (!tlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(packetReceivedEvent.PathIdentity, datagram));
            }

            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacket(
                datagram,
                packetProtectionMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(packetReceivedEvent.PathIdentity, datagram));
            }

            return false;
        }

        return TryProcessHandshakePacketPayload(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            QuicTlsEncryptionLevel.Handshake,
            nowTicks,
            ref effects);
    }

    private bool TryProcessHandshakePacketPayload(
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool processedCryptoFrame = false;
        bool stateChanged = false;
        int payloadOffset = 0;

        while (payloadOffset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[payloadOffset..];
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                if (pingBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += pingBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                return false;
            }

            processedCryptoFrame = true;
            if (!tlsBridgeDriver.TryBufferIncomingCryptoData(
                encryptionLevel,
                cryptoFrame.Offset,
                cryptoFrame.CryptoData.ToArray(),
                out _))
            {
                return false;
            }

            IReadOnlyList<QuicTlsStateUpdate> transcriptUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(
                encryptionLevel);
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.TranscriptAdvanced(encryptionLevel, transcriptUpdates.Count));
            }

            if (transcriptUpdates.Count == 0)
            {
                payloadOffset += bytesConsumed;
                continue;
            }

            bool sawFatalAlert = false;
            foreach (QuicTlsStateUpdate transcriptUpdate in transcriptUpdates)
            {
                stateChanged |= HandleTlsStateUpdated(
                    new QuicConnectionTlsStateUpdatedEvent(nowTicks, transcriptUpdate),
                    nowTicks,
                    ref effects);

                if (transcriptUpdate.Kind == QuicTlsUpdateKind.FatalAlert)
                {
                    sawFatalAlert = true;
                    break;
                }
            }

            if (!sawFatalAlert)
            {
                // All non-fatal transcript updates are surfaced through the runtime so newly available
                // crypto material and handshake state can flush immediately.
            }

            payloadOffset += bytesConsumed;
        }

        stateChanged |= TryFlushInitialPackets(ref effects);
        stateChanged |= TryFlushHandshakePackets(ref effects);

        if (!processedCryptoFrame)
        {
            return false;
        }

        return stateChanged || processedCryptoFrame;
    }

    private bool TryHandleApplicationPacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Active
            || activePath is null
            || !tlsState.OneRttKeysAvailable
            || !tlsState.OneRttOpenPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        bool stateChanged = false;
        if (!handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacket(
            packetReceivedEvent.Datagram.Span,
            tlsState.OneRttOpenPacketProtectionMaterial.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase))
        {
            // The first observed phase-1 packet may already require successor keys.
            if (!tlsBridgeDriver.TryDeriveOneRttSuccessorPacketProtectionMaterial(
                    out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                    out QuicTlsPacketProtectionMaterial successorProtectMaterial)
                || !handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacket(
                    packetReceivedEvent.Datagram.Span,
                    successorOpenMaterial,
                    out openedPacket,
                    out payloadOffset,
                    out payloadLength,
                    out _)
                || !tlsState.TryInstallOneRttKeyUpdate(successorOpenMaterial, successorProtectMaterial)
                || !tlsBridgeDriver.TryDiscardOneRttApplicationTrafficSecrets())
            {
                return false;
            }

            keyPhase = true;
            stateChanged = true;
        }

        if (keyPhase
            && !tlsState.KeyUpdateInstalled
            && tlsState.CurrentOneRttKeyPhase == 0)
        {
            if (!tlsBridgeDriver.TryInstallOneRttKeyUpdate())
            {
                return false;
            }

            stateChanged = true;
        }

        bool processedCryptoFrame = false;
        bool processedStreamFrame = false;
        bool processedMaxStreamsFrame = false;
        ulong originalBidirectionalLimit = streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit;
        ulong originalUnidirectionalLimit = streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit;
        int payloadEnd = payloadOffset + payloadLength;
        int offset = payloadOffset;

        while (offset < payloadEnd)
        {
            ReadOnlySpan<byte> remaining = openedPacket.AsSpan(offset, payloadEnd - offset);
            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed))
            {
                if (paddingBytesConsumed <= 0)
                {
                    return false;
                }

                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                if (pingBytesConsumed <= 0)
                {
                    return false;
                }

                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseStopSendingFrame(remaining, out QuicStopSendingFrame stopSendingFrame, out int stopSendingBytesConsumed))
            {
                if (stopSendingBytesConsumed <= 0)
                {
                    return false;
                }

                if (!TryHandleStopSendingFrame(stopSendingFrame, ref effects))
                {
                    return false;
                }

                stateChanged = true;
                offset += stopSendingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamsFrame(remaining, out QuicMaxStreamsFrame maxStreamsFrame, out int maxStreamsBytesConsumed))
            {
                if (maxStreamsBytesConsumed <= 0)
                {
                    return false;
                }

                if (streamRegistry.Bookkeeping.TryApplyMaxStreamsFrame(maxStreamsFrame))
                {
                    processedMaxStreamsFrame = true;
                    stateChanged = true;
                }

                offset += maxStreamsBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed))
            {
                if (cryptoBytesConsumed <= 0)
                {
                    return false;
                }

                processedCryptoFrame = true;
                if (!tlsBridgeDriver.TryBufferIncomingCryptoData(
                    QuicTlsEncryptionLevel.OneRtt,
                    cryptoFrame.Offset,
                    cryptoFrame.CryptoData.ToArray(),
                    out _))
                {
                    return false;
                }

                IReadOnlyList<QuicTlsStateUpdate> transcriptUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(
                    QuicTlsEncryptionLevel.OneRtt);
                foreach (QuicTlsStateUpdate transcriptUpdate in transcriptUpdates)
                {
                    stateChanged |= HandleTlsStateUpdated(
                        new QuicConnectionTlsStateUpdatedEvent(nowTicks, transcriptUpdate),
                        nowTicks,
                        ref effects);
                }

                offset += cryptoBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseNewConnectionIdFrame(remaining, out QuicNewConnectionIdFrame newConnectionIdFrame, out int newConnectionIdBytesConsumed))
            {
                if (newConnectionIdBytesConsumed <= 0)
                {
                    return false;
                }

                if (!TryHandleNewConnectionIdFrame(newConnectionIdFrame, nowTicks, ref effects, out bool newConnectionIdStateChanged))
                {
                    return false;
                }

                stateChanged |= newConnectionIdStateChanged;
                offset += newConnectionIdBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseResetStreamFrame(remaining, out QuicResetStreamFrame resetStreamFrame, out int resetBytesConsumed))
            {
                if (resetBytesConsumed <= 0)
                {
                    return false;
                }

            if (!TryHandleResetStreamFrame(resetStreamFrame, ref effects))
            {
                return false;
            }

                stateChanged = true;
                offset += resetBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out QuicPathChallengeFrame pathChallengeFrame, out int pathChallengeBytesConsumed))
            {
                if (pathChallengeBytesConsumed <= 0)
                {
                    return false;
                }

                if (TryHandlePathChallengeFrame(
                    packetReceivedEvent.PathIdentity,
                    pathChallengeFrame,
                    nowTicks,
                    ref effects))
                {
                    stateChanged = true;
                }

                offset += pathChallengeBytesConsumed;
                continue;
            }

            if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                return false;
            }

            if (streamFrame.ConsumedLength <= 0)
            {
                return false;
            }

            processedStreamFrame = true;
            bool streamPreviouslyKnown = streamRegistry.Bookkeeping.TryGetStreamSnapshot(streamFrame.StreamId.Value, out _);
            if (!streamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode))
            {
                _ = errorCode;
                return false;
            }

            if (!streamPreviouslyKnown)
            {
                TryQueueInboundStreamId(streamFrame.StreamId.Value);
            }

            stateChanged = true;
            offset += streamFrame.ConsumedLength;
        }

        if (processedMaxStreamsFrame)
        {
            int bidirectionalIncrement = GetPositiveIncrement(
                originalBidirectionalLimit,
                streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit);
            int unidirectionalIncrement = GetPositiveIncrement(
                originalUnidirectionalLimit,
                streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit);

            if (bidirectionalIncrement != 0)
            {
                stateChanged |= TryRetryPendingStreamOpenRequests(true, ref effects);
            }

            if (unidirectionalIncrement != 0)
            {
                stateChanged |= TryRetryPendingStreamOpenRequests(false, ref effects);
            }

            if (bidirectionalIncrement != 0 || unidirectionalIncrement != 0)
            {
                streamCapacityObserver?.Invoke(bidirectionalIncrement, unidirectionalIncrement);
            }
        }

        return processedStreamFrame || processedCryptoFrame || stateChanged;
    }

    private bool TryHandlePathChallengeFrame(
        QuicConnectionPathIdentity pathIdentity,
        QuicPathChallengeFrame pathChallengeFrame,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        Span<byte> responseFrameBuffer = stackalloc byte[16];
        if (!QuicFrameCodec.TryFormatPathResponseFrame(
            new QuicPathResponseFrame(pathChallengeFrame.Data),
            responseFrameBuffer,
            out int responseFrameBytesWritten))
        {
            return false;
        }

        ReadOnlyMemory<byte> responseDatagram = responseFrameBuffer[..responseFrameBytesWritten].ToArray();

        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.AmplificationState.TryConsumeSendBudget(
                responseFrameBytesWritten,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            activePath = currentPath with
            {
                LastActivityTicks = nowTicks,
                AmplificationState = updatedAmplificationState,
            };
        }
        else if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            if (!candidatePath.AmplificationState.TryConsumeSendBudget(
                responseFrameBytesWritten,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            candidatePath = candidatePath with
            {
                LastActivityTicks = nowTicks,
                AmplificationState = updatedAmplificationState,
            };
            candidatePaths[pathIdentity] = candidatePath;
        }
        else
        {
            return false;
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, responseDatagram));
        return true;
    }

    private bool TryHandleNewConnectionIdFrame(
        QuicNewConnectionIdFrame newConnectionIdFrame,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects,
        out bool stateChanged)
    {
        stateChanged = false;

        if (!peerConnectionIdState.TryAcceptNewConnectionId(
            newConnectionIdFrame,
            PeerRequestedZeroLengthConnectionId(),
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged))
        {
            _ = HandleFatalTlsSignal(
                nowTicks,
                errorCode,
                "The peer sent an invalid NEW_CONNECTION_ID frame.",
                ref effects);
            return false;
        }

        if (destinationConnectionIdChanged
            && !TrySetHandshakeDestinationConnectionId(peerConnectionIdState.CurrentDestinationConnectionId.Span))
        {
            _ = HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer connection ID could not be installed.",
                ref effects);
            return false;
        }

        stateChanged = destinationConnectionIdChanged;
        return true;
    }

    private bool TryFlushInitialPackets(ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || initialPacketProtection is null
            || !TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity))
        {
            return false;
        }

        if (retryBootstrapPendingReplay)
        {
            if (retrySourceConnectionId is null
                || retryToken is null
                || initialBootstrapClientHelloBytes is null
                || initialBootstrapClientHelloBytes.Length == 0)
            {
                return false;
            }

            bool replayed = TryFlushRetriedInitialPackets(
                pathIdentity,
                initialBootstrapClientHelloBytes,
                retrySourceConnectionId,
                retryToken,
                initialPacketProtection,
                ref effects);

            if (replayed)
            {
                retryBootstrapPendingReplay = false;
            }

            return replayed;
        }

        if (tlsState.InitialEgressCryptoBuffer.BufferedBytes <= 0)
        {
            return false;
        }

        bool stateChanged = false;
        Span<byte> cryptoBuffer = stackalloc byte[HandshakeEgressChunkBytes];

        while (tlsState.InitialEgressCryptoBuffer.BufferedBytes > 0)
        {
            int requestedBytes = Math.Min(cryptoBuffer.Length, tlsState.InitialEgressCryptoBuffer.BufferedBytes);
            if (requestedBytes <= 0)
            {
                break;
            }

            Span<byte> cryptoChunk = cryptoBuffer[..requestedBytes];
            if (!tlsBridgeDriver.TryPeekOutgoingCryptoData(
                QuicTlsEncryptionLevel.Initial,
                cryptoChunk,
                out ulong cryptoOffset,
                out int cryptoBytesWritten)
                || cryptoBytesWritten <= 0)
            {
                break;
            }

            byte[] protectedPacket;
            bool builtProtectedPacket;
            if (tlsState.Role == QuicTlsRole.Client)
            {
                builtProtectedPacket = handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                    cryptoChunk[..cryptoBytesWritten],
                    cryptoOffset,
                    initialPacketProtection,
                    out ulong packetNumber,
                    out protectedPacket);

                if (!builtProtectedPacket)
                {
                    break;
                }

                if (!tlsBridgeDriver.TryDequeueOutgoingCryptoData(
                    QuicTlsEncryptionLevel.Initial,
                    cryptoChunk[..cryptoBytesWritten],
                    out ulong dequeuedOffset,
                    out int dequeuedBytesWritten)
                    || dequeuedOffset != cryptoOffset
                    || dequeuedBytesWritten != cryptoBytesWritten)
                {
                    break;
                }

                TrackInitialPacket(packetNumber, protectedPacket);
            }
            else
            {
                builtProtectedPacket = handshakeFlowCoordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
                    cryptoChunk[..cryptoBytesWritten],
                    cryptoOffset,
                    initialPacketProtection,
                    out ulong packetNumber,
                    out protectedPacket);

                if (!builtProtectedPacket)
                {
                    break;
                }

                if (!tlsBridgeDriver.TryDequeueOutgoingCryptoData(
                    QuicTlsEncryptionLevel.Initial,
                    cryptoChunk[..cryptoBytesWritten],
                    out ulong dequeuedOffset,
                    out int dequeuedBytesWritten)
                    || dequeuedOffset != cryptoOffset
                    || dequeuedBytesWritten != cryptoBytesWritten)
                {
                    break;
                }

                TrackInitialPacket(packetNumber, protectedPacket);
            }

            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
            tlsState.InitialEgressCryptoBuffer.DiscardFutureFrames();
            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryFlushZeroRttPackets(ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || tlsState.Role != QuicTlsRole.Client
            || zeroRttPacketSent
            || retryBootstrapPendingReplay
            || !HasDormantEarlyDataAttemptReadiness
            || tlsState.OneRttKeysAvailable
            || tlsState.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Rejected
            || initialBootstrapClientHelloBytes is null
            || initialBootstrapClientHelloBytes.Length == 0
            || !TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity)
            || !tlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            return false;
        }

        Span<byte> applicationPayload = stackalloc byte[ApplicationMinimumProtectedPayloadLength];
        applicationPayload.Clear();
        if (!QuicFrameCodec.TryFormatPingFrame(applicationPayload, out int bytesWritten)
            || bytesWritten <= 0)
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryBuildProtectedZeroRttApplicationPacket(
            applicationPayload,
            packetProtectionMaterial,
            out ulong packetNumber,
            out byte[] protectedPacket))
        {
            return false;
        }

        // The zero-RTT bootstrap path emits only a PING probe, so it carries no user data to repair.
        TrackApplicationPacket(packetNumber, protectedPacket, retransmittable: false, probePacket: true);
        zeroRttPacketSent = true;
        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
        return true;
    }

    private bool TryFlushRetriedInitialPackets(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> initialClientHelloBytes,
        ReadOnlySpan<byte> retrySourceConnectionId,
        ReadOnlySpan<byte> retryToken,
        QuicInitialPacketProtection protection,
        ref List<QuicConnectionEffect>? effects)
    {
        if (initialClientHelloBytes.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        Span<byte> cryptoBuffer = stackalloc byte[HandshakeEgressChunkBytes];
        int replayOffset = 0;

        while (replayOffset < initialClientHelloBytes.Length)
        {
            int requestedBytes = Math.Min(cryptoBuffer.Length, initialClientHelloBytes.Length - replayOffset);
            if (requestedBytes <= 0)
            {
                break;
            }

            ReadOnlySpan<byte> cryptoChunk = initialClientHelloBytes.Slice(replayOffset, requestedBytes);
            if (!handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                cryptoChunk,
                (ulong)replayOffset,
                retrySourceConnectionId,
                retryToken,
                protection,
                out ulong packetNumber,
                out byte[] protectedPacket))
            {
                break;
            }

            TrackInitialPacket(packetNumber, protectedPacket);
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
            replayOffset += requestedBytes;
            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryFlushHandshakePackets(ref List<QuicConnectionEffect>? effects)
    {
        if (phase is QuicConnectionPhase.Closing
            or QuicConnectionPhase.Draining
            or QuicConnectionPhase.Discarded
            || activePath is null
            || tlsState.HandshakeEgressCryptoBuffer.BufferedBytes <= 0
            || !tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            return false;
        }

        bool stateChanged = false;
        Span<byte> cryptoBuffer = stackalloc byte[HandshakeEgressChunkBytes];

        while (tlsState.HandshakeEgressCryptoBuffer.BufferedBytes > 0)
        {
            int requestedBytes = Math.Min(cryptoBuffer.Length, tlsState.HandshakeEgressCryptoBuffer.BufferedBytes);
            if (requestedBytes <= 0)
            {
                break;
            }

            Span<byte> cryptoChunk = cryptoBuffer[..requestedBytes];
            if (!tlsBridgeDriver.TryPeekOutgoingCryptoData(
                QuicTlsEncryptionLevel.Handshake,
                cryptoChunk,
                out ulong cryptoOffset,
                out int cryptoBytesWritten)
                || cryptoBytesWritten <= 0)
            {
                break;
            }

            if (!handshakeFlowCoordinator.TryBuildProtectedHandshakePacket(
                cryptoChunk[..cryptoBytesWritten],
                cryptoOffset,
                packetProtectionMaterial,
                out ulong packetNumber,
                out byte[] protectedPacket))
            {
                break;
            }

            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.AmplificationState.TryConsumeSendBudget(
                protectedPacket.Length,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                break;
            }

            if (!tlsBridgeDriver.TryDequeueOutgoingCryptoData(
                QuicTlsEncryptionLevel.Handshake,
                cryptoChunk[..cryptoBytesWritten],
                out ulong dequeuedOffset,
                out int dequeuedBytesWritten)
                || dequeuedOffset != cryptoOffset
                || dequeuedBytesWritten != cryptoBytesWritten)
            {
                break;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            TrackHandshakePacket(packetNumber, protectedPacket);
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                protectedPacket));
            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryFlushHandshakeDonePacket(ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Active
            || tlsState.Role != QuicTlsRole.Server
            || handshakeDonePacketSent
            || !peerHandshakeTranscriptCompleted
            || activePath is null
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        if (!TryBuildOutboundHandshakeDonePayload(out byte[] applicationPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            applicationPayload,
            "The connection runtime could not protect the HANDSHAKE_DONE packet.",
            "The connection cannot send the HANDSHAKE_DONE packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };
        handshakeDonePacketSent = true;
        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity)
    {
        if (activePath is not null)
        {
            pathIdentity = activePath.Value.Identity;
            return true;
        }

        if (tlsState.Role == QuicTlsRole.Client
            && bootstrapOutboundPathIdentity.HasValue)
        {
            pathIdentity = bootstrapOutboundPathIdentity.Value;
            return true;
        }

        pathIdentity = default;
        return false;
    }

    private bool TryValidateStreamSendBoundary(out Exception? exception)
    {
        if (terminalState is QuicConnectionTerminalState terminalStateValue)
        {
            exception = CreateTerminalException(terminalStateValue);
            return false;
        }

        if (IsDisposed)
        {
            exception = new ObjectDisposedException(nameof(QuicConnectionRuntime));
            return false;
        }

        if (phase != QuicConnectionPhase.Active || activePath is null)
        {
            exception = new InvalidOperationException("The connection is not established.");
            return false;
        }

        if (!tlsState.OneRttKeysAvailable
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            exception = new InvalidOperationException("The connection is not ready to send application stream data.");
            return false;
        }

        exception = null;
        return true;
    }

    private bool TryReleasePeerStreamCapacity(ulong streamId, ref List<QuicConnectionEffect>? effects)
    {
        if (!TryValidateStreamSendBoundary(out Exception? exception))
        {
            _ = exception;
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryPeekPeerStreamCapacityRelease(streamId, out QuicMaxStreamsFrame maxStreamsFrame))
        {
            return false;
        }

        if (!TryBuildOutboundMaxStreamsPayload(maxStreamsFrame, out byte[] streamPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream capacity release packet.",
            "The connection cannot send the stream capacity release packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out exception))
        {
            return false;
        }

        if (!streamRegistry.Bookkeeping.TryCommitPeerStreamCapacityRelease(streamId, maxStreamsFrame))
        {
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        return true;
    }

    private bool TryProtectAndAccountApplicationPayload(
        ReadOnlySpan<byte> payload,
        string protectFailureMessage,
        string amplificationFailureMessage,
        out QuicConnectionActivePathRecord currentPath,
        out QuicConnectionPathAmplificationState updatedAmplificationState,
        out byte[] protectedPacket,
        out Exception? exception)
    {
        currentPath = default;
        updatedAmplificationState = default;
        protectedPacket = [];

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhase == 1,
            out ulong packetNumber,
            out protectedPacket))
        {
            exception = new InvalidOperationException(protectFailureMessage);
            return false;
        }

        currentPath = activePath!.Value;
        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            protectedPacket.Length,
            out updatedAmplificationState))
        {
            exception = new InvalidOperationException(amplificationFailureMessage);
            return false;
        }

        TrackApplicationPacket(packetNumber, protectedPacket);
        exception = null;
        return true;
    }

    private void TrackApplicationPacket(
        ulong packetNumber,
        byte[] protectedPacket,
        bool retransmittable = true,
        bool probePacket = false)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            (ulong)protectedPacket.Length,
            GetElapsedMicros(lastTransitionTicks),
            ProbePacket: probePacket,
            Retransmittable: retransmittable,
            PacketBytes: protectedPacket));
    }

    private void TrackInitialPacket(ulong packetNumber, byte[] protectedPacket)
    {
        TrackCryptoPacket(QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, packetNumber, protectedPacket);
    }

    private void TrackHandshakePacket(ulong packetNumber, byte[] protectedPacket)
    {
        TrackCryptoPacket(QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, packetNumber, protectedPacket);
    }

    private void TrackCryptoPacket(
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel encryptionLevel,
        ulong packetNumber,
        byte[] protectedPacket)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            (ulong)protectedPacket.Length,
            GetElapsedMicros(lastTransitionTicks),
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(encryptionLevel),
            PacketBytes: protectedPacket));
    }

    private bool TryBuildOutboundStreamPayload(
        ulong streamId,
        ulong offset,
        ReadOnlySpan<byte> streamData,
        bool fin,
        out byte[] payload)
    {
        payload = [];

        byte frameType = OutboundStreamControlFrameType;
        if (offset != 0)
        {
            frameType |= QuicStreamFrameBits.OffsetBitMask;
        }

        if (fin)
        {
            frameType |= QuicStreamFrameBits.FinBitMask;
        }

        int bufferLength = Math.Max(ApplicationMinimumProtectedPayloadLength, streamData.Length + 32);
        byte[] buffer = new byte[bufferLength];
        if (!QuicFrameCodec.TryFormatStreamFrame(
            frameType,
            streamId,
            offset,
            streamData,
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundResetPayload(
        ulong streamId,
        ulong applicationErrorCode,
        ulong finalSize,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatResetStreamFrame(
            new QuicResetStreamFrame(streamId, applicationErrorCode, finalSize),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundStopSendingPayload(
        ulong streamId,
        ulong applicationErrorCode,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatStopSendingFrame(
            new QuicStopSendingFrame(streamId, applicationErrorCode),
            buffer,
            out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxDataPayload(
        QuicMaxDataFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxDataFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxStreamDataPayload(
        QuicMaxStreamDataFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxStreamDataFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundDataBlockedPayload(
        QuicDataBlockedFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatDataBlockedFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundStreamDataBlockedPayload(
        QuicStreamDataBlockedFrame frame,
        out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    private bool TryBuildOutboundMaxStreamsPayload(QuicMaxStreamsFrame frame, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 64)];
        if (!QuicFrameCodec.TryFormatMaxStreamsFrame(frame, buffer, out int frameBytesWritten))
        {
            return false;
        }

        if (frameBytesWritten > buffer.Length)
        {
            return false;
        }

        if (frameBytesWritten < buffer.Length)
        {
            buffer.AsSpan(frameBytesWritten).Fill(0);
        }

        payload = buffer;
        return true;
    }

    internal bool TryBuildOutboundHandshakeDonePayload(out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[1];
        if (!QuicFrameCodec.TryFormatHandshakeDoneFrame(default, buffer, out int frameBytesWritten)
            || frameBytesWritten != buffer.Length)
        {
            return false;
        }

        payload = buffer;
        return true;
    }

    private bool TryHandleResetStreamFrame(QuicResetStreamFrame resetStreamFrame, ref List<QuicConnectionEffect>? effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveResetStreamFrame(
            resetStreamFrame,
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode,
            suppressResetSignalWhenDataRecvd: true))
        {
            _ = errorCode;
            return false;
        }

        if (maxDataFrame.MaximumData != 0)
        {
            _ = TryEmitFlowControlCreditUpdate(maxDataFrame, default, ref effects);
        }

        if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(resetStreamFrame.StreamId, out QuicConnectionStreamSnapshot snapshot)
            && snapshot.ReceiveState == QuicStreamReceiveState.ResetRecvd)
        {
            NotifyStreamObservers(
                resetStreamFrame.StreamId,
                new QuicStreamNotification(
                    QuicStreamNotificationKind.ReadAborted,
                    CreateStreamReadAbortedException(resetStreamFrame.ApplicationProtocolErrorCode)));

            TryReleasePeerStreamCapacity(resetStreamFrame.StreamId, ref effects);
        }

        return true;
    }

    private bool TryHandleStopSendingFrame(QuicStopSendingFrame stopSendingFrame, ref List<QuicConnectionEffect>? effects)
    {
        if (!streamRegistry.Bookkeeping.TryReceiveStopSendingFrame(
            stopSendingFrame,
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode))
        {
            _ = errorCode;
            return false;
        }

        if (!TryBuildOutboundResetPayload(
            resetStreamFrame.StreamId,
            resetStreamFrame.ApplicationProtocolErrorCode,
            resetStreamFrame.FinalSize,
            out byte[] streamPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            streamPayload,
            "The connection runtime could not protect the stream reset packet.",
            "The connection cannot send the stream reset packet.",
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));

        NotifyStreamObservers(
            stopSendingFrame.StreamId,
            new QuicStreamNotification(
                QuicStreamNotificationKind.WriteAborted,
                CreateStreamWriteAbortedException(stopSendingFrame.ApplicationProtocolErrorCode)));

        TryReleasePeerStreamCapacity(stopSendingFrame.StreamId, ref effects);
        return true;
    }

    private void TryQueueInboundStreamId(ulong streamId)
    {
        _ = inboundStreamIds.Writer.TryWrite(streamId);
    }

    private void CompletePendingStreamOperations(Exception completionException)
    {
        CompleteInboundStreamQueue(completionException);
        CompletePendingStreamOpenRequests(completionException);
        CompletePendingStreamActionRequests(completionException);
        pendingApplicationSendRequests.Clear();
        pendingApplicationSendDelayDueTicks = null;
    }

    private void CompleteInboundStreamQueue(Exception completionException)
    {
        inboundStreamQueueCompletionException ??= completionException;

        while (inboundStreamIds.Reader.TryRead(out _))
        {
            // Drain queued stream identifiers so pending accepts observe terminal completion.
        }

        inboundStreamIds.Writer.TryComplete(completionException);
    }

    private void CompletePendingStreamOpenRequests(Exception completionException)
    {
        if (pendingStreamOpenRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, TaskCompletionSource<ulong>> entry in pendingStreamOpenRequests.ToArray())
        {
            if (TryRemovePendingStreamOpenRequest(entry.Key, out TaskCompletionSource<ulong>? completion))
            {
                completion!.TrySetException(completionException);
            }
        }
    }

    private bool TryRemovePendingStreamOpenRequest(long requestId, out TaskCompletionSource<ulong>? completion)
    {
        if (!pendingStreamOpenRequests.TryRemove(requestId, out completion))
        {
            pendingStreamOpenTypes.TryRemove(requestId, out _);
            return false;
        }

        pendingStreamOpenTypes.TryRemove(requestId, out _);
        return true;
    }

    private void CompletePendingStreamActionRequests(Exception completionException)
    {
        if (pendingStreamActionRequests.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<long, TaskCompletionSource<object?>> entry in pendingStreamActionRequests.ToArray())
        {
            if (pendingStreamActionRequests.TryRemove(entry.Key, out TaskCompletionSource<object?>? completion))
            {
                completion.TrySetException(completionException);
            }
        }
    }

    private void NotifyStreamObservers(ulong streamId, QuicStreamNotification notification)
    {
        if (!streamObservers.TryGetValue(streamId, out ConcurrentDictionary<long, Action<QuicStreamNotification>>? observers))
        {
            return;
        }

        foreach (Action<QuicStreamNotification> observer in observers.Values)
        {
            try
            {
                observer(notification);
            }
            catch
            {
                // Stream observer failures remain local to the public facade boundary.
            }
        }
    }

    private void NotifyAllStreamObservers(Exception completionException)
    {
        if (streamObservers.IsEmpty)
        {
            return;
        }

        foreach (KeyValuePair<ulong, ConcurrentDictionary<long, Action<QuicStreamNotification>>> entry in streamObservers)
        {
            QuicStreamNotification notification = new(
                QuicStreamNotificationKind.ConnectionTerminated,
                completionException);

            foreach (Action<QuicStreamNotification> observer in entry.Value.Values)
            {
                try
                {
                    observer(notification);
                }
                catch
                {
                    // Stream observer failures remain local to the public facade boundary.
                }
            }
        }
    }

    private static Exception CreateTerminalException(QuicConnectionTerminalState terminalState)
    {
        if (terminalState.Close.TransportErrorCode.HasValue)
        {
            return new QuicException(
                QuicError.TransportError,
                null,
                (long)terminalState.Close.TransportErrorCode.Value,
                terminalState.Close.ReasonPhrase ?? "The connection terminated.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.IdleTimeout)
        {
            return new QuicException(
                QuicError.ConnectionIdle,
                null,
                terminalState.Close.ReasonPhrase ?? "The connection idled.");
        }

        if (terminalState.Origin == QuicConnectionCloseOrigin.VersionNegotiation)
        {
            return new QuicException(
                QuicError.VersionNegotiationError,
                null,
                terminalState.Close.ReasonPhrase ?? "The connection could not negotiate a compatible version.");
        }

        long? applicationErrorCode = terminalState.Close.ApplicationErrorCode.HasValue
            ? checked((long)terminalState.Close.ApplicationErrorCode.Value)
            : null;

        return new QuicException(
            QuicError.ConnectionAborted,
            applicationErrorCode,
            terminalState.Close.ReasonPhrase ?? "The connection terminated.");
    }

    private static Exception CreateLocalOperationAbortedException(string message)
    {
        return new QuicException(
            QuicError.OperationAborted,
            null,
            message);
    }

    private static Exception CreateStreamReadAbortedException(ulong applicationErrorCode)
    {
        return new QuicException(
            QuicError.StreamAborted,
            checked((long)applicationErrorCode),
            "The peer aborted the stream.");
    }

    private static Exception CreateStreamWriteAbortedException(ulong applicationErrorCode)
    {
        return new QuicException(
            QuicError.StreamAborted,
            checked((long)applicationErrorCode),
            "The peer requested the stream stop sending.");
    }

    private bool TryCommitLocalTransportParametersFromTlsBridgeState(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicTransportParameters? localTransportParameters = tlsState.LocalTransportParameters;
        if (localTransportParameters is null)
        {
            return false;
        }

        return ApplyTransportParameters(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: nowTicks,
                TransportFlags: QuicConnectionTransportState.None,
                LocalMaxIdleTimeoutMicros: localTransportParameters.MaxIdleTimeout),
            nowTicks,
            ref effects);
    }

    private bool TryCaptureOwnedResumptionTicketSnapshot(long nowTicks)
    {
        if (ownedResumptionTicketBytes is not null
            || tlsState.Role != QuicTlsRole.Client
            || !tlsState.HasPostHandshakeTicket
            || !tlsState.PostHandshakeTicketLifetimeSeconds.HasValue
            || !tlsState.PostHandshakeTicketAgeAdd.HasValue)
        {
            return false;
        }

        ReadOnlyMemory<byte> ticketBytes = tlsState.PostHandshakeTicketBytes;
        if (ticketBytes.IsEmpty)
        {
            return false;
        }

        ownedResumptionTicketBytes = ticketBytes.ToArray();
        ownedResumptionTicketNonce = tlsState.PostHandshakeTicketNonce.ToArray();
        ownedResumptionTicketLifetimeSeconds = tlsState.PostHandshakeTicketLifetimeSeconds;
        ownedResumptionTicketAgeAdd = tlsState.PostHandshakeTicketAgeAdd;
        ownedResumptionTicketMaxEarlyDataSize = tlsState.PostHandshakeTicketMaxEarlyDataSize;
        ownedResumptionTicketPeerTransportParameters = tlsState.PeerTransportParametersSnapshot;
        ownedResumptionTicketCapturedAtTicks = nowTicks;
        _ = TryCaptureResumptionMasterSecret();
        return true;
    }

    private bool TryCaptureResumptionMasterSecret()
    {
        if (resumptionMasterSecret is not null
            || tlsState.Role != QuicTlsRole.Client
            || !tlsState.HasResumptionMasterSecret)
        {
            return false;
        }

        ReadOnlyMemory<byte> secretBytes = tlsState.ResumptionMasterSecret;
        if (secretBytes.IsEmpty)
        {
            return false;
        }

        resumptionMasterSecret = secretBytes.ToArray();
        return true;
    }

    private bool TryCommitPeerTransportParametersFromTlsBridgeDriver(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicTransportParameters? stagedPeerTransportParameters = tlsState.StagedPeerTransportParameters;
        if (stagedPeerTransportParameters is null)
        {
            return false;
        }

        if (!tlsState.CanCommitPeerTransportParameters(stagedPeerTransportParameters))
        {
            return false;
        }

        IReadOnlyList<QuicTlsStateUpdate> updates = tlsBridgeDriver.CommitPeerTransportParameters(
            stagedPeerTransportParameters);
        if (updates.Count == 0)
        {
            return false;
        }

        bool stateChanged = false;
        foreach (QuicTlsStateUpdate update in updates)
        {
            stateChanged |= HandleTlsStateUpdated(
                new QuicConnectionTlsStateUpdatedEvent(nowTicks, update),
                nowTicks,
                ref effects);
        }

        return stateChanged;
    }

    private bool TryCommitPeerTransportParametersFromTlsBridgeState(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicTransportParameters? peerTransportParameters = tlsState.PeerTransportParameters;
        if (peerTransportParameters is null)
        {
            return false;
        }

        QuicTransportParameterRole receiverRole = tlsState.Role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;

        ReadOnlySpan<byte> retrySourceConnectionIdSpan = this.retrySourceConnectionId is null
            ? ReadOnlySpan<byte>.Empty
            : this.retrySourceConnectionId;

        ReadOnlySpan<byte> handshakeDestinationConnectionId = handshakeFlowCoordinator.DestinationConnectionId.Span;
        if (!handshakeFlowCoordinator.InitialDestinationConnectionId.IsEmpty
            && !handshakeDestinationConnectionId.IsEmpty
            && !QuicTransportParametersCodec.TryValidateConnectionIdBindings(
                receiverRole,
                handshakeFlowCoordinator.InitialDestinationConnectionId.Span,
                handshakeDestinationConnectionId,
                retrySourceConnectionIdSpan.Length > 0,
                retrySourceConnectionIdSpan,
                peerTransportParameters,
                out QuicConnectionIdBindingValidationError validationError))
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.TransportParameterError,
                $"The peer transport parameters failed connection ID binding validation: {validationError}.",
                ref effects);
        }

        bool stateChanged = TryCommitPeerStreamLimits(
            peerTransportParameters,
            out int bidirectionalIncrement,
            out int unidirectionalIncrement);

        if (bidirectionalIncrement != 0 || unidirectionalIncrement != 0)
        {
            streamCapacityObserver?.Invoke(bidirectionalIncrement, unidirectionalIncrement);
        }

        QuicConnectionTransportState committedTransportFlags = QuicConnectionTransportState.PeerTransportParametersCommitted;
        if (peerTransportParameters.DisableActiveMigration)
        {
            committedTransportFlags |= QuicConnectionTransportState.DisableActiveMigration;
        }

        stateChanged |= ApplyTransportParameters(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: nowTicks,
                TransportFlags: committedTransportFlags,
                PeerMaxIdleTimeoutMicros: peerTransportParameters.MaxIdleTimeout),
            nowTicks,
            ref effects);
        return stateChanged;
    }

    private bool HandleTlsKeyDiscard(QuicTlsEncryptionLevel encryptionLevel, ref List<QuicConnectionEffect>? effects)
    {
        _ = effects;

        return encryptionLevel switch
        {
            QuicTlsEncryptionLevel.Initial => sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial),
            QuicTlsEncryptionLevel.Handshake => sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake),
            QuicTlsEncryptionLevel.OneRtt => false,
            _ => false,
        };
    }

    private bool HandleFatalTlsSignal(
        long observedAtTicks,
        QuicTransportErrorCode errorCode,
        string? description,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: errorCode,
            ApplicationErrorCode: null,
            TriggeringFrameType: null,
            ReasonPhrase: description);

        return HandleLocalCloseRequested(
            new QuicConnectionLocalCloseRequestedEvent(observedAtTicks, closeMetadata),
            observedAtTicks,
            ref effects);
    }

    private bool ApplyTransportParameters(
        QuicConnectionTransportParametersCommittedEvent transportParametersCommittedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = false;

        QuicConnectionTransportState updatedFlags = transportFlags | transportParametersCommittedEvent.TransportFlags;
        if (updatedFlags != transportFlags)
        {
            transportFlags = updatedFlags;
            stateChanged = true;
        }

        if (transportParametersCommittedEvent.LocalMaxIdleTimeoutMicros.HasValue
            && localMaxIdleTimeoutMicros != transportParametersCommittedEvent.LocalMaxIdleTimeoutMicros.Value)
        {
            localMaxIdleTimeoutMicros = transportParametersCommittedEvent.LocalMaxIdleTimeoutMicros.Value;
            stateChanged = true;
        }

        if (transportParametersCommittedEvent.PeerMaxIdleTimeoutMicros.HasValue
            && peerMaxIdleTimeoutMicros != transportParametersCommittedEvent.PeerMaxIdleTimeoutMicros.Value)
        {
            peerMaxIdleTimeoutMicros = transportParametersCommittedEvent.PeerMaxIdleTimeoutMicros.Value;
            stateChanged = true;
        }

        if (transportParametersCommittedEvent.CurrentProbeTimeoutMicros.HasValue)
        {
            if (transportParametersCommittedEvent.CurrentProbeTimeoutMicros.Value == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(transportParametersCommittedEvent), "CurrentProbeTimeoutMicros must be greater than zero.");
            }

            if (currentProbeTimeoutMicros != transportParametersCommittedEvent.CurrentProbeTimeoutMicros.Value)
            {
                currentProbeTimeoutMicros = transportParametersCommittedEvent.CurrentProbeTimeoutMicros.Value;
                stateChanged = true;
            }
        }

        if (RecomputeIdleTimeoutState(nowTicks))
        {
            stateChanged = true;
        }

        if (stateChanged)
        {
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }

        return stateChanged;
    }

    private bool TryCommitPeerStreamLimits(
        QuicTransportParameters peerTransportParameters,
        out int bidirectionalIncrement,
        out int unidirectionalIncrement)
    {
        bidirectionalIncrement = 0;
        unidirectionalIncrement = 0;
        bool stateChanged = false;
        ulong originalBidirectionalLimit = streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit;
        ulong originalUnidirectionalLimit = streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit;

        if (peerTransportParameters.InitialMaxStreamsBidi is ulong initialMaxStreamsBidi)
        {
            stateChanged |= streamRegistry.Bookkeeping.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, initialMaxStreamsBidi));
        }

        if (peerTransportParameters.InitialMaxStreamsUni is ulong initialMaxStreamsUni)
        {
            stateChanged |= streamRegistry.Bookkeeping.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(false, initialMaxStreamsUni));
        }

        bidirectionalIncrement = GetPositiveIncrement(
            originalBidirectionalLimit,
            streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit);
        unidirectionalIncrement = GetPositiveIncrement(
            originalUnidirectionalLimit,
            streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit);

        return stateChanged;
    }

    private static int GetPositiveIncrement(ulong originalValue, ulong updatedValue)
    {
        if (updatedValue <= originalValue)
        {
            return 0;
        }

        return checked((int)(updatedValue - originalValue));
    }

    private bool HandlePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (SendingMode == QuicConnectionSendingMode.None)
        {
            return false;
        }

        bool stateChanged = false;
        int payloadBytes = packetReceivedEvent.Datagram.Length;

        if (activePath is null)
        {
            stateChanged = InitializeActivePath(packetReceivedEvent.PathIdentity, payloadBytes, nowTicks);
        }
        else if (EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, packetReceivedEvent.PathIdentity))
        {
            stateChanged = UpdateActivePathTraffic(payloadBytes, nowTicks);
        }
        else
        {
            stateChanged = HandleAddressChangePacket(packetReceivedEvent.PathIdentity, payloadBytes, nowTicks, ref effects);
        }

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordPeerPacketProcessed(GetElapsedMicros(nowTicks));
            stateChanged = true;
        }

        if (phase == QuicConnectionPhase.Establishing)
        {
            stateChanged |= TryHandleInitialPacketReceived(packetReceivedEvent, nowTicks, ref effects);
            stateChanged |= TryHandleHandshakePacketReceived(packetReceivedEvent, nowTicks, ref effects);
        }
        else if (phase == QuicConnectionPhase.Active)
        {
            stateChanged |= TryHandleApplicationPacketReceived(packetReceivedEvent, nowTicks, ref effects);
        }
        else if (phase == QuicConnectionPhase.Closing)
        {
            if (terminalState is QuicConnectionTerminalState terminalStateValue)
            {
                AppendConnectionClosePacket(ref effects, terminalStateValue.Close);
            }
        }

        stateChanged |= TryFlushHandshakePackets(ref effects);
        stateChanged |= TryFlushHandshakeDonePacket(ref effects);

        if (stateChanged)
        {
            hasSuccessfullyProcessedAnotherPacket = true;
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }

        return stateChanged;
    }

    private bool HandlePathValidationSucceeded(
        QuicConnectionPathValidationSucceededEvent pathValidationSucceededEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryGetCandidatePath(pathValidationSucceededEvent.PathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            return false;
        }

        if (candidatePath.Validation.IsAbandoned || (candidatePath.Validation.IsValidated && !candidatePath.Validation.IsAbandoned))
        {
            return false;
        }

        QuicConnectionPathIdentity? originalPathIdentity = activePath?.Identity;
        bool preferredAddressPathValidated = IsPreferredAddressPath(pathValidationSucceededEvent.PathIdentity);

        candidatePath = candidatePath with
        {
            Validation = candidatePath.Validation with
            {
                IsValidated = true,
                IsAbandoned = false,
                ValidationDeadlineTicks = null,
                ChallengeSentAtTicks = candidatePath.Validation.ChallengeSentAtTicks ?? nowTicks,
            },
            AmplificationState = candidatePath.AmplificationState.MarkAddressValidated(),
            LastActivityTicks = nowTicks,
        };
        candidatePaths[pathValidationSucceededEvent.PathIdentity] = candidatePath;

        AppendRecentlyValidatedPath(candidatePath.Identity, nowTicks, candidatePath.SavedRecoverySnapshot, candidatePath.AmplificationState);
        lastValidatedRemoteAddress = candidatePath.Identity.RemoteAddress;

        bool stateChanged = true;
        if (preferredAddressPathValidated
            && originalPathIdentity.HasValue)
        {
            stateChanged |= TryAbandonOriginalCandidatePathAfterPreferredAddressValidation(
                originalPathIdentity.Value,
                pathValidationSucceededEvent.PathIdentity,
                nowTicks);
        }

        if (CanPromoteActivePathMigration()
            && TryPromoteValidatedCandidatePath(pathValidationSucceededEvent.PathIdentity, nowTicks, ref effects))
        {
            stateChanged = true;
        }

        UpdatePeerAddressValidationFlag();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        stateChanged |= TryFlushHandshakePackets(ref effects);
        stateChanged |= TryFlushHandshakeDonePacket(ref effects);
        return stateChanged;
    }

    private bool HandlePathValidationFailed(
        QuicConnectionPathValidationFailedEvent pathValidationFailedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryGetCandidatePath(pathValidationFailedEvent.PathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            if (HasValidatedPath)
            {
                AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
            }

            return false;
        }

        candidatePath = candidatePath with
        {
            Validation = candidatePath.Validation with
            {
                IsAbandoned = true,
                ValidationDeadlineTicks = null,
            },
            LastActivityTicks = nowTicks,
        };
        candidatePaths[pathValidationFailedEvent.PathIdentity] = candidatePath;

        bool stateChanged = true;

        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, candidatePath.Identity))
        {
            if (TryPromoteFallbackValidatedPath(nowTicks, ref effects))
            {
                stateChanged = true;
            }
            else if (activePath is not null)
            {
                activePath = activePath.Value with
                {
                    IsValidated = false,
                    RecoverySnapshot = null,
                    LastActivityTicks = nowTicks,
                };
            }
        }

        if (!HasValidatedPath)
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.PathValidationFailedNoValidatedPathsRemain(pathValidationFailedEvent.PathIdentity));
            }
        }

        UpdatePeerAddressValidationFlag();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return stateChanged;
    }

    private bool HandlePathValidationTimerExpired(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = false;
        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> entry in candidatePaths.ToArray())
        {
            QuicConnectionCandidatePathRecord candidatePath = entry.Value;
            if (candidatePath.Validation.IsValidated
                || candidatePath.Validation.IsAbandoned
                || !candidatePath.Validation.ValidationDeadlineTicks.HasValue
                || candidatePath.Validation.ValidationDeadlineTicks.Value > nowTicks)
            {
                continue;
            }

            candidatePath = candidatePath with
            {
                LastActivityTicks = nowTicks,
            };

            if (!TrySendPathValidationChallenge(entry.Key, nowTicks, ref candidatePath, ref effects))
            {
                candidatePath = candidatePath with
                {
                    Validation = candidatePath.Validation with
                    {
                        ValidationDeadlineTicks = SaturatingAdd(
                            nowTicks,
                            ConvertMicrosToTicks(currentProbeTimeoutMicros)),
                    },
                };
                candidatePaths[entry.Key] = candidatePath;
            }

            stateChanged = true;
        }

        if (stateChanged)
        {
            UpdatePeerAddressValidationFlag();
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }

        return stateChanged;
    }

    private bool HandleLocalCloseRequested(
        QuicConnectionLocalCloseRequestedEvent localCloseRequestedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (phase is QuicConnectionPhase.Closing or QuicConnectionPhase.Draining or QuicConnectionPhase.Discarded)
        {
            return false;
        }

        EnterTerminalPhase(
            QuicConnectionPhase.Closing,
            QuicConnectionCloseOrigin.Local,
            localCloseRequestedEvent.Close,
            nowTicks,
            preserveTerminalEndTicks: false);

        AppendTerminalEffects(ref effects, emitClosePacket: true);
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool HandleConnectionCloseFrameReceived(
        QuicConnectionConnectionCloseFrameReceivedEvent connectionCloseFrameReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (phase is QuicConnectionPhase.Draining or QuicConnectionPhase.Discarded)
        {
            return false;
        }

        bool shouldSendReplyClosePacket = phase != QuicConnectionPhase.Closing;

        EnterTerminalPhase(
            QuicConnectionPhase.Draining,
            QuicConnectionCloseOrigin.Remote,
            connectionCloseFrameReceivedEvent.Close,
            nowTicks,
            preserveTerminalEndTicks: phase == QuicConnectionPhase.Closing);

        AppendTerminalEffects(ref effects, emitClosePacket: false);
        if (shouldSendReplyClosePacket)
        {
            AppendConnectionClosePacket(ref effects, CreatePeerConnectionCloseReplyMetadata());
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool HandleAcceptedStatelessReset(
        QuicConnectionAcceptedStatelessResetEvent acceptedStatelessResetEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (phase is QuicConnectionPhase.Draining or QuicConnectionPhase.Discarded)
        {
            return false;
        }

        RetireAllStatelessResetTokens(ref effects);
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.AcceptedStatelessReset(
                acceptedStatelessResetEvent.PathIdentity,
                acceptedStatelessResetEvent.ConnectionId));
        }

        EnterTerminalPhase(
            QuicConnectionPhase.Draining,
            QuicConnectionCloseOrigin.StatelessReset,
            default,
            nowTicks,
            preserveTerminalEndTicks: phase == QuicConnectionPhase.Closing);

        AppendTerminalEffects(ref effects, emitClosePacket: false);
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool HandleConnectionIdIssued(
        QuicConnectionConnectionIdIssuedEvent connectionIdIssuedEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        if (connectionIdIssuedEvent.StatelessResetToken.Length != QuicStatelessReset.StatelessResetTokenLength
            || statelessResetTokensByConnectionId.ContainsKey(connectionIdIssuedEvent.ConnectionId))
        {
            return false;
        }

        byte[] token = connectionIdIssuedEvent.StatelessResetToken.ToArray();
        statelessResetTokensByConnectionId.Add(connectionIdIssuedEvent.ConnectionId, token);
        AppendEffect(ref effects, new QuicConnectionRegisterStatelessResetTokenEffect(connectionIdIssuedEvent.ConnectionId, token));
        return true;
    }

    private bool HandleConnectionIdRetired(
        QuicConnectionConnectionIdRetiredEvent connectionIdRetiredEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!statelessResetTokensByConnectionId.Remove(connectionIdRetiredEvent.ConnectionId))
        {
            return false;
        }

        AppendEffect(ref effects, new QuicConnectionRetireStatelessResetTokenEffect(connectionIdRetiredEvent.ConnectionId));
        return true;
    }

    private bool HandleConnectionIdAcknowledged(QuicConnectionConnectionIdAcknowledgedEvent connectionIdAcknowledgedEvent)
    {
        _ = connectionIdAcknowledgedEvent;
        return false;
    }

    internal QuicConnectionEffect[] SetTimerDeadline(QuicConnectionTimerKind timerKind, long? dueTicks)
    {
        QuicConnectionTimerSchedule currentSchedule = GetTimerSchedule(timerKind);
        if (currentSchedule.DueTicks == dueTicks)
        {
            return Array.Empty<QuicConnectionEffect>();
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(currentSchedule.Generation);
        timerState = timerState.WithSchedule(timerKind, dueTicks, nextGeneration);

        if (!dueTicks.HasValue)
        {
            return [new QuicConnectionCancelTimerEffect(timerKind, nextGeneration)];
        }

        QuicConnectionTimerPriority priority = timerState.CreatePriority(dueTicks.Value);
        timerState = timerState.AdvancePrioritySequence();
        return [new QuicConnectionArmTimerEffect(timerKind, nextGeneration, priority)];
    }

    private QuicConnectionTimerSchedule GetTimerSchedule(QuicConnectionTimerKind timerKind)
    {
        return timerKind switch
        {
            QuicConnectionTimerKind.IdleTimeout => timerState.IdleTimeout,
            QuicConnectionTimerKind.CloseLifetime => timerState.CloseLifetime,
            QuicConnectionTimerKind.DrainLifetime => timerState.DrainLifetime,
            QuicConnectionTimerKind.PathValidation => timerState.PathValidation,
            QuicConnectionTimerKind.ApplicationSendDelay => timerState.ApplicationSendDelay,
            _ => throw new ArgumentOutOfRangeException(nameof(timerKind)),
        };
    }

    private bool TryHandleTimerExpired(
        QuicConnectionTimerExpiredEvent timerExpiredEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!timerState.IsCurrent(timerExpiredEvent.TimerKind, timerExpiredEvent.Generation))
        {
            return false;
        }

        ulong nextGeneration = QuicConnectionTimerDeadlineState.IncrementCounter(
            timerState.GetGeneration(timerExpiredEvent.TimerKind));

        timerState = timerState.WithSchedule(timerExpiredEvent.TimerKind, null, nextGeneration);

        switch (timerExpiredEvent.TimerKind)
        {
            case QuicConnectionTimerKind.IdleTimeout:
                return HandleIdleTimeoutExpired(nowTicks, ref effects);
            case QuicConnectionTimerKind.CloseLifetime:
                return phase == QuicConnectionPhase.Closing
                    && DiscardConnection(nowTicks, QuicConnectionCloseOrigin.Local, terminalState?.Close ?? default, ref effects);
            case QuicConnectionTimerKind.DrainLifetime:
                return phase == QuicConnectionPhase.Draining
                    && DiscardConnection(nowTicks, terminalState?.Origin ?? QuicConnectionCloseOrigin.Remote, terminalState?.Close ?? default, ref effects);
            case QuicConnectionTimerKind.PathValidation:
                return HandlePathValidationTimerExpired(nowTicks, ref effects);
            case QuicConnectionTimerKind.ApplicationSendDelay:
                return FlushPendingApplicationSends(nowTicks, ref effects);
            default:
                throw new ArgumentOutOfRangeException(nameof(timerExpiredEvent), "TimerKind was not recognized.");
        }
    }

    private bool HandleIdleTimeoutExpired(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (phase is QuicConnectionPhase.Closing or QuicConnectionPhase.Draining or QuicConnectionPhase.Discarded)
        {
            return false;
        }

        return DiscardConnection(nowTicks, QuicConnectionCloseOrigin.IdleTimeout, default, ref effects);
    }

    private bool DiscardConnection(
        long nowTicks,
        QuicConnectionCloseOrigin origin,
        QuicConnectionCloseMetadata closeMetadata,
        ref List<QuicConnectionEffect>? effects)
    {
        phase = QuicConnectionPhase.Discarded;
        idleTimeoutState = null;
        terminalEndTicks = null;
        terminalState = new QuicConnectionTerminalState(
            QuicConnectionPhase.Discarded,
            origin,
            closeMetadata,
            nowTicks);

        Exception terminalException = CreateTerminalException(terminalState.Value);
        CompletePendingStreamOperations(terminalException);
        NotifyAllStreamObservers(terminalException);
        AppendEffect(ref effects, new QuicConnectionNotifyStreamsOfTerminalStateEffect(terminalState.Value));
        AppendEffect(ref effects, new QuicConnectionDiscardConnectionStateEffect(terminalState));
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private void RetireAllStatelessResetTokens(ref List<QuicConnectionEffect>? effects)
    {
        if (statelessResetTokensByConnectionId.Count == 0)
        {
            return;
        }

        ulong[] connectionIds = statelessResetTokensByConnectionId.Keys.ToArray();
        foreach (ulong connectionId in connectionIds)
        {
            if (statelessResetTokensByConnectionId.Remove(connectionId))
            {
                AppendEffect(ref effects, new QuicConnectionRetireStatelessResetTokenEffect(connectionId));
            }
        }
    }

    private bool RecomputeIdleTimeoutState(long nowTicks)
    {
        if (!QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros,
            peerMaxIdleTimeoutMicros,
            currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros))
        {
            if (idleTimeoutState is null)
            {
                return false;
            }

            idleTimeoutState = null;
            return true;
        }

        if (idleTimeoutState is not null
            && idleTimeoutState.EffectiveIdleTimeoutMicros == effectiveIdleTimeoutMicros)
        {
            return false;
        }

        idleTimeoutState = new QuicIdleTimeoutState(effectiveIdleTimeoutMicros);
        idleTimeoutState.RecordPeerPacketProcessed(GetElapsedMicros(nowTicks));
        return true;
    }

    private bool InitializeActivePath(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks)
    {
        QuicConnectionPathAmplificationState amplificationState = default;
        if (!amplificationState.TryRegisterReceivedDatagramPayloadBytes(payloadBytes, uniquelyAttributedToSingleConnection: true, out amplificationState))
        {
            return false;
        }

        bool trustedReuse = TryGetRecentlyValidatedPath(pathIdentity, out QuicConnectionValidatedPathRecord recentlyValidatedPath);
        if (trustedReuse)
        {
            amplificationState = amplificationState.MarkAddressValidated();
        }

        activePath = new QuicConnectionActivePathRecord(
            pathIdentity,
            ActivatedAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            IsValidated: trustedReuse || transportFlags.HasFlag(QuicConnectionTransportState.PeerAddressValidated),
            RecoverySnapshot: trustedReuse ? recentlyValidatedPath.SavedRecoverySnapshot : null)
        {
            AmplificationState = amplificationState,
        };

        if (activePath.Value.IsValidated)
        {
            lastValidatedRemoteAddress = pathIdentity.RemoteAddress;
        }

        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool UpdateActivePathTraffic(int payloadBytes, long nowTicks)
    {
        if (activePath is null)
        {
            return false;
        }

        QuicConnectionActivePathRecord path = activePath.Value;
        if (!path.AmplificationState.TryRegisterReceivedDatagramPayloadBytes(
            payloadBytes,
            uniquelyAttributedToSingleConnection: true,
            out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return false;
        }

        QuicConnectionActivePathRecord updatedPath = path with
        {
            LastActivityTicks = nowTicks,
            AmplificationState = updatedAmplificationState,
        };

        if (updatedPath == path)
        {
            return false;
        }

        activePath = updatedPath;
        if (updatedPath.IsValidated)
        {
            lastValidatedRemoteAddress = updatedPath.Identity.RemoteAddress;
        }

        return true;
    }

    private bool HandleAddressChangePacket(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionPathClassification classification = ClassifyPathChange(pathIdentity);
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.AddressChangeClassified(pathIdentity, classification));
        }

        if (preferredAddressOldPathIdentity.HasValue
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(preferredAddressOldPathIdentity.Value, pathIdentity))
        {
            return false;
        }

        if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            return HandleExistingCandidatePath(pathIdentity, payloadBytes, nowTicks, ref candidatePath, ref effects);
        }

        if (TryGetRecentlyValidatedPath(pathIdentity, out QuicConnectionValidatedPathRecord recentlyValidatedPath))
        {
            return TryHandleTrustedPathReuse(pathIdentity, payloadBytes, nowTicks, recentlyValidatedPath, ref effects);
        }

        if (MaximumCandidatePaths == 0 || candidatePaths.Count >= MaximumCandidatePaths)
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.CandidatePathBudgetExhausted(pathIdentity));
            }

            return false;
        }

        return TryCreateCandidatePath(pathIdentity, payloadBytes, nowTicks, recentlyValidatedPath: null, ref effects);
    }

    private bool HandleExistingCandidatePath(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        ref QuicConnectionCandidatePathRecord candidatePath,
        ref List<QuicConnectionEffect>? effects)
    {
        if (candidatePath.Validation.IsValidated && !candidatePath.Validation.IsAbandoned)
        {
            candidatePath = candidatePath with
            {
                LastActivityTicks = nowTicks,
            };
            bool pathUpdated = true;
            if (candidatePath.AmplificationState.TryRegisterReceivedDatagramPayloadBytes(
                payloadBytes,
                uniquelyAttributedToSingleConnection: true,
                out QuicConnectionPathAmplificationState validatedAmplificationState))
            {
                candidatePath = candidatePath with
                {
                    AmplificationState = validatedAmplificationState,
                };
            }

            candidatePaths[pathIdentity] = candidatePath;

            if (CanPromoteActivePathMigration())
            {
                return TryPromoteValidatedCandidatePath(pathIdentity, nowTicks, ref effects);
            }

            UpdatePeerAddressValidationFlag();
            return pathUpdated;
        }

        if (candidatePath.Validation.IsAbandoned)
        {
            return TryCreateCandidatePath(pathIdentity, payloadBytes, nowTicks, recentlyValidatedPath: null, ref effects);
        }

        bool stateChanged = true;
        if (candidatePath.AmplificationState.TryRegisterReceivedDatagramPayloadBytes(
            payloadBytes,
            uniquelyAttributedToSingleConnection: true,
            out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            candidatePath = candidatePath with
            {
                AmplificationState = updatedAmplificationState,
            };
        }

        candidatePath = candidatePath with
        {
            LastActivityTicks = nowTicks,
        };

        if (!candidatePath.Validation.ValidationDeadlineTicks.HasValue
            || candidatePath.Validation.ValidationDeadlineTicks.Value <= nowTicks)
        {
            stateChanged |= TrySendPathValidationChallenge(pathIdentity, nowTicks, ref candidatePath, ref effects);
        }

        candidatePaths[pathIdentity] = candidatePath;
        UpdatePeerAddressValidationFlag();

        return stateChanged;
    }

    private bool TryHandleTrustedPathReuse(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        QuicConnectionValidatedPathRecord recentlyValidatedPath,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionPathAmplificationState amplificationState = recentlyValidatedPath.AmplificationState.MarkAddressValidated();
        if (!amplificationState.TryRegisterReceivedDatagramPayloadBytes(
            payloadBytes,
            uniquelyAttributedToSingleConnection: true,
            out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return false;
        }

        QuicConnectionCandidatePathRecord candidatePath = new(
            pathIdentity,
            DiscoveredAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            Validation: new QuicConnectionPathValidationState(
                Generation: 0,
                IsValidated: true,
                IsAbandoned: false,
                ChallengeSendCount: 0,
                ChallengeSentAtTicks: null,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: recentlyValidatedPath.SavedRecoverySnapshot)
        {
            AmplificationState = updatedAmplificationState.MarkAddressValidated(),
        };

        candidatePaths[pathIdentity] = candidatePath;
        AppendRecentlyValidatedPath(pathIdentity, nowTicks, recentlyValidatedPath.SavedRecoverySnapshot, candidatePath.AmplificationState);
        lastValidatedRemoteAddress = pathIdentity.RemoteAddress;

        if (CanPromoteActivePathMigration())
        {
            return TryPromoteValidatedCandidatePath(pathIdentity, nowTicks, ref effects);
        }

        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool TryCreateCandidatePath(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        QuicConnectionValidatedPathRecord? recentlyValidatedPath,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionPathAmplificationState amplificationState = default;
        if (!amplificationState.TryRegisterReceivedDatagramPayloadBytes(payloadBytes, uniquelyAttributedToSingleConnection: true, out amplificationState))
        {
            return false;
        }

        bool isTrustedReuse = recentlyValidatedPath.HasValue;
        if (isTrustedReuse)
        {
            amplificationState = amplificationState.MarkAddressValidated();
        }

        QuicConnectionCandidatePathRecord candidatePath = new(
            pathIdentity,
            DiscoveredAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            Validation: new QuicConnectionPathValidationState(
                Generation: 0,
                IsValidated: isTrustedReuse,
                IsAbandoned: false,
                ChallengeSendCount: 0,
                ChallengeSentAtTicks: null,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: recentlyValidatedPath?.SavedRecoverySnapshot)
        {
            AmplificationState = amplificationState,
        };

        candidatePaths[pathIdentity] = candidatePath;

        if (!isTrustedReuse)
        {
            TrySendPathValidationChallenge(pathIdentity, nowTicks, ref candidatePath, ref effects);
            candidatePaths[pathIdentity] = candidatePath;
        }
        else
        {
            AppendRecentlyValidatedPath(pathIdentity, nowTicks, recentlyValidatedPath?.SavedRecoverySnapshot, candidatePath.AmplificationState);
        }

        if (isTrustedReuse)
        {
            lastValidatedRemoteAddress = pathIdentity.RemoteAddress;
        }

        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool TrySendPathValidationChallenge(
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks,
        ref QuicConnectionCandidatePathRecord candidatePath,
        ref List<QuicConnectionEffect>? effects)
    {
        if (candidatePath.Validation.IsValidated || candidatePath.Validation.IsAbandoned)
        {
            return false;
        }

        Span<byte> challengePayload = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        if (!QuicPathValidation.TryGeneratePathChallengeData(challengePayload, out int challengePayloadBytesWritten))
        {
            return false;
        }

        Span<byte> challengePayloadBuffer = challengePayload[..challengePayloadBytesWritten];
        Span<byte> challengeFrameBuffer = stackalloc byte[16];
        if (!QuicFrameCodec.TryFormatPathChallengeFrame(
            new QuicPathChallengeFrame(challengePayloadBuffer),
            challengeFrameBuffer,
            out int challengeFrameBytesWritten))
        {
            return false;
        }

        int totalPayloadLength = challengeFrameBytesWritten;
        byte[] datagram = challengeFrameBuffer[..challengeFrameBytesWritten].ToArray();

        int paddingLength = 0;
        if (QuicPathValidation.TryGetPathValidationDatagramPaddingLength(totalPayloadLength, out int computedPaddingLength)
            && computedPaddingLength > 0)
        {
            paddingLength = computedPaddingLength;
        }

        if (paddingLength > 0
            && candidatePath.AmplificationState.CanSend(totalPayloadLength + paddingLength))
        {
            QuicAntiAmplificationBudget paddingBudget = new();
            if (!paddingBudget.TryRegisterReceivedDatagramPayloadBytes(paddingLength, uniquelyAttributedToSingleConnection: true))
            {
                return false;
            }

            byte[] paddedDatagram = new byte[totalPayloadLength + paddingLength];
            datagram.CopyTo(paddedDatagram, 0);
            if (!QuicPathValidation.TryFormatPathValidationDatagramPadding(
                totalPayloadLength,
                paddingBudget,
                paddedDatagram.AsSpan(totalPayloadLength),
                out int paddingBytesWritten))
            {
                return false;
            }

            totalPayloadLength += paddingBytesWritten;
            datagram = paddedDatagram;
        }

        if (!candidatePath.AmplificationState.TryConsumeSendBudget(totalPayloadLength, out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return false;
        }

        candidatePath = candidatePath with
        {
            AmplificationState = updatedAmplificationState,
            Validation = candidatePath.Validation with
            {
                Generation = QuicConnectionTimerDeadlineState.IncrementCounter(candidatePath.Validation.Generation),
                ChallengeSendCount = candidatePath.Validation.ChallengeSendCount + 1,
                ChallengeSentAtTicks = nowTicks,
                ValidationDeadlineTicks = SaturatingAdd(nowTicks, ConvertMicrosToTicks(currentProbeTimeoutMicros)),
                ChallengePayload = challengePayload[..challengePayloadBytesWritten].ToArray(),
            },
        };

        candidatePaths[pathIdentity] = candidatePath;
        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, datagram));
        return true;
    }

    private bool TryGetCandidatePath(QuicConnectionPathIdentity pathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
    {
        return candidatePaths.TryGetValue(pathIdentity, out candidatePath);
    }

    private bool TryGetRecentlyValidatedPath(QuicConnectionPathIdentity pathIdentity, out QuicConnectionValidatedPathRecord validatedPath)
    {
        return recentlyValidatedPaths.TryGetValue(pathIdentity, out validatedPath);
    }

    private QuicConnectionPathClassification ClassifyPathChange(QuicConnectionPathIdentity pathIdentity)
    {
        if (TryGetRecentlyValidatedPath(pathIdentity, out _))
        {
            return QuicConnectionPathClassification.PreferredAddressTransition;
        }

        if (string.Equals(lastValidatedRemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal))
        {
            return QuicConnectionPathClassification.ProbableNatRebinding;
        }

        return peerHandshakeTranscriptCompleted ? QuicConnectionPathClassification.MigrationCandidate : QuicConnectionPathClassification.ProbableNatRebinding;
    }

    private void AppendRecentlyValidatedPath(
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks,
        QuicConnectionPathRecoverySnapshot? savedRecoverySnapshot,
        QuicConnectionPathAmplificationState amplificationState)
    {
        if (MaximumRecentlyValidatedPaths == 0)
        {
            return;
        }

        recentlyValidatedPaths[pathIdentity] = new QuicConnectionValidatedPathRecord(
            pathIdentity,
            ValidatedAtTicks: nowTicks,
            SavedRecoverySnapshot: savedRecoverySnapshot)
        {
            LastActivityTicks = nowTicks,
            AmplificationState = amplificationState.MarkAddressValidated(),
        };

        if (recentlyValidatedPaths.Count <= MaximumRecentlyValidatedPaths)
        {
            return;
        }

        QuicConnectionPathIdentity? candidateToRemove = null;
        long oldestActivityTicks = long.MaxValue;
        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> entry in recentlyValidatedPaths)
        {
            if (EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(entry.Key, pathIdentity))
            {
                continue;
            }

            if (entry.Value.LastActivityTicks < oldestActivityTicks)
            {
                oldestActivityTicks = entry.Value.LastActivityTicks;
                candidateToRemove = entry.Key;
            }
        }

        if (candidateToRemove.HasValue)
        {
            recentlyValidatedPaths.Remove(candidateToRemove.Value);
        }
    }

    private bool TryPromoteValidatedCandidatePath(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionPathIdentity? bestPathIdentity = null;
        long bestActivityTicks = long.MinValue;

        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> entry in candidatePaths)
        {
            QuicConnectionCandidatePathRecord candidatePath = entry.Value;
            if (!candidatePath.Validation.IsValidated || candidatePath.Validation.IsAbandoned)
            {
                continue;
            }

            if (candidatePath.LastActivityTicks > bestActivityTicks)
            {
                bestActivityTicks = candidatePath.LastActivityTicks;
                bestPathIdentity = entry.Key;
            }
        }

        if (!bestPathIdentity.HasValue)
        {
            return false;
        }

        return TryPromoteValidatedCandidatePath(bestPathIdentity.Value, nowTicks, ref effects);
    }

    private bool TryPromoteValidatedCandidatePath(
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
            || !candidatePath.Validation.IsValidated
            || candidatePath.Validation.IsAbandoned)
        {
            return false;
        }

        bool activePathChanged = activePath is null
            || !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity);
        bool preserveCurrentRecoveryState = activePath is not null
            && IsPortOnlyPeerAddressChange(activePath.Value.Identity, pathIdentity);

        if (activePathChanged && !CanPromoteActivePathMigration())
        {
            return false;
        }

        if (activePath is not null && activePathChanged && !preserveCurrentRecoveryState)
        {
            ResetRecoveryStateForNewPath();
        }

        MaybeRememberPreferredAddressMigrationSource(pathIdentity);

        if (activePath is not null
            && !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity)
            && activePath.Value.IsValidated)
        {
            AppendRecentlyValidatedPath(
                activePath.Value.Identity,
                nowTicks,
                activePath.Value.RecoverySnapshot,
                activePath.Value.AmplificationState);
        }

        AppendRecentlyValidatedPath(
            pathIdentity,
            nowTicks,
            candidatePath.SavedRecoverySnapshot,
            candidatePath.AmplificationState);

        QuicConnectionActivePathRecord updatedActivePath = new(
            pathIdentity,
            ActivatedAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            IsValidated: true,
            RecoverySnapshot: candidatePath.SavedRecoverySnapshot)
        {
            AmplificationState = candidatePath.AmplificationState.MarkAddressValidated(),
        };

        activePath = updatedActivePath;
        candidatePaths.Remove(pathIdentity);
        lastValidatedRemoteAddress = pathIdentity.RemoteAddress;
        UpdatePeerAddressValidationFlag();

        if (activePathChanged)
        {
            AppendEffect(ref effects, new QuicConnectionPromoteActivePathEffect(
                pathIdentity,
                RestoreSavedState: preserveCurrentRecoveryState));
        }

        return true;
    }

    private bool TryPromoteFallbackValidatedPath(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (!CanPromoteActivePathMigration())
        {
            return false;
        }

        if (recentlyValidatedPaths.Count == 0)
        {
            return false;
        }

        QuicConnectionValidatedPathRecord? bestCandidate = null;
        QuicConnectionPathIdentity? bestPathIdentity = null;
        long bestActivityTicks = long.MinValue;

        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> entry in recentlyValidatedPaths)
        {
            if (activePath is not null
                && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, entry.Key))
            {
                continue;
            }

            if (entry.Value.LastActivityTicks > bestActivityTicks)
            {
                bestActivityTicks = entry.Value.LastActivityTicks;
                bestCandidate = entry.Value;
                bestPathIdentity = entry.Key;
            }
        }

        if (!bestCandidate.HasValue || !bestPathIdentity.HasValue)
        {
            return false;
        }

        bool preserveCurrentRecoveryState = activePath is not null
            && IsPortOnlyPeerAddressChange(activePath.Value.Identity, bestPathIdentity.Value);
        if (activePath is not null && !preserveCurrentRecoveryState)
        {
            ResetRecoveryStateForNewPath();
        }

        MaybeRememberPreferredAddressMigrationSource(bestPathIdentity.Value);

        QuicConnectionActivePathRecord promotedPath = new(
            bestPathIdentity.Value,
            ActivatedAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            IsValidated: true,
            RecoverySnapshot: bestCandidate.Value.SavedRecoverySnapshot)
        {
            AmplificationState = bestCandidate.Value.AmplificationState.MarkAddressValidated(),
        };

        AppendRecentlyValidatedPath(
            bestPathIdentity.Value,
            nowTicks,
            bestCandidate.Value.SavedRecoverySnapshot,
            bestCandidate.Value.AmplificationState);

        activePath = promotedPath;
        lastValidatedRemoteAddress = bestPathIdentity.Value.RemoteAddress;
        UpdatePeerAddressValidationFlag();
        AppendEffect(ref effects, new QuicConnectionPromoteActivePathEffect(
            bestPathIdentity.Value,
            RestoreSavedState: preserveCurrentRecoveryState));
        return true;
    }

    private bool TryAbandonOriginalCandidatePathAfterPreferredAddressValidation(
        QuicConnectionPathIdentity originalPathIdentity,
        QuicConnectionPathIdentity preferredPathIdentity,
        long nowTicks)
    {
        bool stateChanged = false;

        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> entry in candidatePaths.ToArray())
        {
            QuicConnectionCandidatePathRecord candidatePath = entry.Value;
            if (candidatePath.Validation.IsValidated
                || candidatePath.Validation.IsAbandoned)
            {
                continue;
            }

            if (!string.Equals(candidatePath.Identity.RemoteAddress, originalPathIdentity.RemoteAddress, StringComparison.Ordinal)
                || candidatePath.Identity.RemotePort != originalPathIdentity.RemotePort
                || !string.Equals(candidatePath.Identity.LocalAddress, preferredPathIdentity.LocalAddress, StringComparison.Ordinal)
                || candidatePath.Identity.LocalPort != preferredPathIdentity.LocalPort)
            {
                continue;
            }

            candidatePath = candidatePath with
            {
                Validation = candidatePath.Validation with
                {
                    IsAbandoned = true,
                    ValidationDeadlineTicks = null,
                },
                LastActivityTicks = nowTicks,
            };

            candidatePaths[entry.Key] = candidatePath;
            stateChanged = true;
        }

        return stateChanged;
    }

    private void ResetRecoveryStateForNewPath()
    {
        // A real peer-address change starts the new path with fresh recovery state so stale
        // packets from the old path cannot keep influencing congestion or PTO decisions, but ACK
        // history must survive so previously received packets still drive ACK generation.
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial, discardAckGenerationState: false);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake, discardAckGenerationState: false);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData, discardAckGenerationState: false);
        sendRuntime.FlowController.CongestionControlState.Reset();
    }

    private static bool IsPortOnlyPeerAddressChange(
        QuicConnectionPathIdentity currentPathIdentity,
        QuicConnectionPathIdentity newPathIdentity)
    {
        return string.Equals(currentPathIdentity.RemoteAddress, newPathIdentity.RemoteAddress, StringComparison.Ordinal)
            && currentPathIdentity.RemotePort.HasValue
            && newPathIdentity.RemotePort.HasValue
            && currentPathIdentity.RemotePort.Value != newPathIdentity.RemotePort.Value;
    }

    private void MaybeRememberPreferredAddressMigrationSource(QuicConnectionPathIdentity pathIdentity)
    {
        if (preferredAddressOldPathIdentity.HasValue
            || activePath is null
            || EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity)
            || !IsPreferredAddressPath(pathIdentity))
        {
            return;
        }

        preferredAddressOldPathIdentity = activePath.Value.Identity;
    }

    private bool IsPreferredAddressPath(QuicConnectionPathIdentity pathIdentity)
    {
        QuicPreferredAddress? preferredAddress = tlsState.PeerTransportParameters?.PreferredAddress;
        if (preferredAddress is null)
        {
            return false;
        }

        return MatchesPreferredAddress(pathIdentity, preferredAddress.IPv4Address, preferredAddress.IPv4Port)
            || MatchesPreferredAddress(pathIdentity, preferredAddress.IPv6Address, preferredAddress.IPv6Port);
    }

    private static bool MatchesPreferredAddress(
        QuicConnectionPathIdentity pathIdentity,
        byte[] addressBytes,
        ushort port)
    {
        if (addressBytes.Length is not (PreferredAddressIPv4BytesLength or PreferredAddressIPv6BytesLength)
            || !pathIdentity.RemotePort.HasValue
            || pathIdentity.RemotePort.Value != port)
        {
            return false;
        }

        return string.Equals(
            new IPAddress(addressBytes).ToString(),
            pathIdentity.RemoteAddress,
            StringComparison.Ordinal);
    }

    private bool CanPromoteActivePathMigration()
    {
        if (!peerHandshakeTranscriptCompleted)
        {
            return false;
        }

        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active)
        {
            return false;
        }

        return !transportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration)
            && !PeerRequestedZeroLengthConnectionId();
    }

    private bool PeerRequestedZeroLengthConnectionId()
    {
        return tlsState.PeerTransportParameters?.InitialSourceConnectionId is { Length: 0 };
    }

    private void UpdatePeerAddressValidationFlag()
    {
        bool shouldBeValidated = HasValidatedPath;
        bool isCurrentlyValidated = transportFlags.HasFlag(QuicConnectionTransportState.PeerAddressValidated);

        if (shouldBeValidated == isCurrentlyValidated)
        {
            return;
        }

        transportFlags = shouldBeValidated
            ? transportFlags | QuicConnectionTransportState.PeerAddressValidated
            : transportFlags & ~QuicConnectionTransportState.PeerAddressValidated;
    }

    private void EnterTerminalPhase(
        QuicConnectionPhase nextPhase,
        QuicConnectionCloseOrigin origin,
        QuicConnectionCloseMetadata closeMetadata,
        long nowTicks,
        bool preserveTerminalEndTicks)
    {
        phase = nextPhase;

        if (!preserveTerminalEndTicks || !terminalEndTicks.HasValue)
        {
            terminalEndTicks = ComputeTerminalEndTicks(nowTicks);
        }

        idleTimeoutState = null;
        terminalState = new QuicConnectionTerminalState(
            nextPhase,
            origin,
            closeMetadata,
            nowTicks);

        Exception terminalException = CreateTerminalException(terminalState.Value);
        CompletePendingStreamOperations(terminalException);
        NotifyAllStreamObservers(terminalException);
    }

    private void AppendTerminalEffects(ref List<QuicConnectionEffect>? effects, bool emitClosePacket)
    {
        if (terminalState.HasValue)
        {
            AppendEffect(ref effects, new QuicConnectionNotifyStreamsOfTerminalStateEffect(terminalState.Value));
        }

        if (!emitClosePacket
            || activePath is null
            || SendingMode != QuicConnectionSendingMode.CloseOnly
            || terminalState is null)
        {
            return;
        }

        AppendConnectionClosePacket(ref effects, terminalState.Value.Close);
    }

    private void AppendConnectionClosePacket(
        ref List<QuicConnectionEffect>? effects,
        QuicConnectionCloseMetadata closeMetadata)
    {
        if (activePath is null)
        {
            return;
        }

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata);
        QuicConnectionActivePathRecord currentPath = activePath.Value;
        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            closePayload.Length,
            out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            closePayload));
    }

    private static QuicConnectionCloseMetadata CreatePeerConnectionCloseReplyMetadata()
    {
        return new QuicConnectionCloseMetadata(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);
    }

    private QuicConnectionEffect[] RecomputeLifecycleTimerEffects()
    {
        List<QuicConnectionEffect> effects = [];
        long? idleDueTicks = phase switch
        {
            QuicConnectionPhase.Establishing or QuicConnectionPhase.Active when idleTimeoutState is not null
                => GetAbsoluteTicks(idleTimeoutState.IdleTimeoutDeadlineMicros),
            _ => null,
        };

        long? pathValidationDueTicks = GetEarliestPathValidationDueTicks();
        long? applicationSendDelayDueTicks = pendingApplicationSendRequests.Count > 0
            ? pendingApplicationSendDelayDueTicks
            : null;

        long? closeDueTicks = phase == QuicConnectionPhase.Closing ? terminalEndTicks : null;
        long? drainDueTicks = phase == QuicConnectionPhase.Draining ? terminalEndTicks : null;

        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, idleDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, closeDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.DrainLifetime, drainDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.PathValidation, pathValidationDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.ApplicationSendDelay, applicationSendDelayDueTicks));
        return effects.ToArray();
    }

    private long? GetEarliestPathValidationDueTicks()
    {
        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active)
        {
            return null;
        }

        long? dueTicks = null;
        foreach (QuicConnectionCandidatePathRecord candidatePath in candidatePaths.Values)
        {
            if (candidatePath.Validation.IsValidated
                || candidatePath.Validation.IsAbandoned
                || !candidatePath.Validation.ValidationDeadlineTicks.HasValue)
            {
                continue;
            }

            long candidateDueTicks = candidatePath.Validation.ValidationDeadlineTicks.Value;
            if (!dueTicks.HasValue || candidateDueTicks < dueTicks.Value)
            {
                dueTicks = candidateDueTicks;
            }
        }

        return dueTicks;
    }

    private long ComputeTerminalEndTicks(long nowTicks)
    {
        ulong terminalLifetimeMicros = MultiplySaturating(currentProbeTimeoutMicros, TerminalLifetimePtoMultiplier);
        return SaturatingAdd(nowTicks, ConvertMicrosToTicks(terminalLifetimeMicros));
    }

    private ulong GetElapsedMicros(long nowTicks)
    {
        long elapsedTicks = nowTicks - timeOriginTicks;
        if (elapsedTicks <= 0)
        {
            return 0;
        }

        return ConvertTicksToMicros(elapsedTicks);
    }

    private long GetAbsoluteTicks(ulong absoluteMicros)
    {
        return SaturatingAdd(timeOriginTicks, ConvertMicrosToTicks(absoluteMicros));
    }

    private static ReadOnlyMemory<byte> FormatConnectionClosePayload(QuicConnectionCloseMetadata closeMetadata)
    {
        byte[] reasonBytes = closeMetadata.ReasonPhrase is null
            ? []
            : Encoding.UTF8.GetBytes(closeMetadata.ReasonPhrase);

        QuicConnectionCloseFrame frame = closeMetadata.ApplicationErrorCode.HasValue
            ? new QuicConnectionCloseFrame(closeMetadata.ApplicationErrorCode.Value, reasonBytes)
            : new QuicConnectionCloseFrame(
                closeMetadata.TransportErrorCode ?? QuicTransportErrorCode.NoError,
                closeMetadata.TriggeringFrameType ?? 0,
                reasonBytes);

        byte[] destination = new byte[DefaultCloseFrameOverheadBytes + reasonBytes.Length];
        if (!QuicFrameCodec.TryFormatConnectionCloseFrame(frame, destination, out int bytesWritten))
        {
            throw new InvalidOperationException("The runtime could not format the CONNECTION_CLOSE payload.");
        }

        return destination.AsMemory(0, bytesWritten);
    }

    private static ulong ConvertTicksToMicros(long ticks)
    {
        if (ticks <= 0)
        {
            return 0;
        }

        ulong numerator = unchecked((ulong)ticks);
        if (numerator > ulong.MaxValue / MicrosecondsPerSecond)
        {
            return ulong.MaxValue;
        }

        return (numerator * MicrosecondsPerSecond) / (ulong)Stopwatch.Frequency;
    }

    private static long ConvertMicrosToTicks(ulong micros)
    {
        if (micros == 0)
        {
            return 0;
        }

        ulong frequency = (ulong)Stopwatch.Frequency;
        ulong wholeTicks = micros > ulong.MaxValue / frequency
            ? ulong.MaxValue
            : micros * frequency;

        ulong roundedUp = wholeTicks == ulong.MaxValue
            ? wholeTicks
            : wholeTicks + (MicrosecondsPerSecond - 1);

        ulong ticks = roundedUp / MicrosecondsPerSecond;
        return ticks >= long.MaxValue ? long.MaxValue : (long)ticks;
    }

    private static ulong MultiplySaturating(ulong value, ulong multiplier)
    {
        if (value == 0 || multiplier == 0)
        {
            return 0;
        }

        if (value > ulong.MaxValue / multiplier)
        {
            return ulong.MaxValue;
        }

        return value * multiplier;
    }

    private static long SaturatingAdd(long left, long right)
    {
        if (right <= 0)
        {
            return left;
        }

        if (left > long.MaxValue - right)
        {
            return long.MaxValue;
        }

        return left + right;
    }

    private sealed record PendingApplicationSendRequest(ulong StreamId, byte[] StreamPayload);

    private void EmitDiagnostic(ref List<QuicConnectionEffect>? effects, QuicDiagnosticEvent diagnosticEvent)
    {
        diagnosticsSink.Emit(diagnosticEvent);
        AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(diagnosticEvent));
    }

    private static void AppendEffect(ref List<QuicConnectionEffect>? effects, QuicConnectionEffect effect)
    {
        (effects ??= []).Add(effect);
    }

    private static void AppendEffects(ref List<QuicConnectionEffect>? effects, QuicConnectionEffect[] additionalEffects)
    {
        if (additionalEffects.Length == 0)
        {
            return;
        }

        effects ??= [];
        effects.AddRange(additionalEffects);
    }
}
