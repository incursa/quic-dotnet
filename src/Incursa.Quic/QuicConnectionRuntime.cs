using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Channels;

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
// - QuicConnectionRuntime.Lifecycle.cs owns terminal transitions, diagnostics, and shared helpers.

internal sealed partial class QuicConnectionRuntime : IAsyncDisposable, IDisposable
{
    private const ulong TerminalLifetimePtoMultiplier = 3;
    private const ulong MicrosecondsPerSecond = 1_000_000UL;
    private const int DefaultCloseFrameOverheadBytes = 32;
    private const int NewTokenBytesLength = 16;
    private const int PreferredAddressIPv4BytesLength = sizeof(uint);
    private const int PreferredAddressIPv6BytesLength = 16;
    private const ulong ApplicationSendDelayMicros = 1_000UL;
    // Hold slightly underfilled application writes long enough to coalesce a follow-up FIN
    // or sibling frame into one 1-RTT packet instead of emitting a second tiny packet.
    private const int ApplicationSendDelayThresholdBytes = 32;
    private const int HandshakeEgressChunkBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;
    private const int MaximumBufferedEstablishmentHandshakePackets = 8;
    private const byte OutboundStreamControlFrameType = QuicStreamFrameBits.StreamFrameTypeMinimum | QuicStreamFrameBits.LengthBitMask;
    private const int ApplicationMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;

    private readonly IMonotonicClock clock;
    private readonly QuicConnectionSendRuntime sendRuntime;
    private readonly QuicRecoveryController recoveryController;
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
    private readonly Dictionary<string, QuicConnectionNewTokenEmissionRecord> newTokenEmissionsByRemoteAddress = new(StringComparer.Ordinal);
    private readonly List<BufferedEstablishmentHandshakePacket> bufferedEstablishmentHandshakePackets = [];
    private readonly QuicConnectionPeerConnectionIdState peerConnectionIdState = new();
    private readonly long timeOriginTicks;
    private readonly QuicHandshakeFlowCoordinator handshakeFlowCoordinator;
    private readonly QuicClientCertificatePolicySnapshot? clientCertificatePolicySnapshot;
    private readonly QuicDetachedResumptionTicketSnapshot? dormantDetachedResumptionTicketSnapshot;
    private readonly IQuicDiagnosticsSink diagnosticsSink;
    private readonly bool diagnosticsEnabled;
    private readonly QuicTransportTlsBridgeState tlsState;
    private readonly QuicTlsTransportBridgeDriver tlsBridgeDriver;
    private readonly QuicConnectionVersionProfile versionProfile;
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
    private byte[]? observedPeerInitialSourceConnectionId;
    private byte[]? observedPeerInitialCryptoFrameData;
    private bool retryBootstrapPendingReplay;
    private bool zeroRttPacketSent;
    private bool handshakeDonePacketSent;
    private bool hasSuccessfullyProcessedAnotherPacket;
    private ulong highestConnectionIdIssuedToPeer;

    private int consumerStarted;
    private int disposed;
    private Task? processingTask;
    private bool peerHandshakeTranscriptCompleted;
    private bool handshakeConfirmed;
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
    private ulong largestObservedApplicationPacketNumber;
    private ulong lowestObservedCurrentOneRttKeyPhasePacketNumber;
    private uint observedCurrentOneRttKeyPhase;
    private long nextStreamActionRequestId;
    private long nextStreamObserverId;
    private Exception? inboundStreamQueueCompletionException;
    private Func<QuicConnectionEvent, bool>? localApiEventDispatcher;
    private Action<int, int>? streamCapacityObserver;
    private long? pendingApplicationSendDelayDueTicks;
    private bool hasObservedApplicationPacketNumber;
    private bool hasObservedCurrentOneRttKeyPhasePacketNumber;

    private sealed record BufferedEstablishmentHandshakePacket(
        QuicConnectionPathIdentity PathIdentity,
        byte[] SourceConnectionId,
        byte[] Datagram);

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
        uint[]? supportedVersions = null)
    {
        this.clock = clock ?? new MonotonicClock();
        timeOriginTicks = this.clock.Ticks;
        sendRuntime = new QuicConnectionSendRuntime();
        recoveryController = new QuicRecoveryController();
        streamRegistry = new QuicConnectionStreamRegistry(bookkeeping);
        handshakeFlowCoordinator = new QuicHandshakeFlowCoordinator(enableRandomizedSpinBitSelection: enableRandomizedSpinBitSelection);
        this.clientCertificatePolicySnapshot = clientCertificatePolicySnapshot;
        this.diagnosticsSink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSink);
        diagnosticsEnabled = this.diagnosticsSink.IsEnabled;
        uint[] supportedVersionSnapshot = supportedVersions is { Length: > 0 }
            ? (uint[])supportedVersions.Clone()
            : [QuicVersionNegotiation.Version1];
        versionProfile = new QuicConnectionVersionProfile(supportedVersionSnapshot);
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

    internal bool HandshakeConfirmed => tlsState.Role == QuicTlsRole.Server
        ? peerHandshakeTranscriptCompleted
        : handshakeConfirmed;

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

    internal QuicConnectionVersionProfile VersionProfile => versionProfile;

    internal ReadOnlyMemory<byte> CurrentPeerDestinationConnectionId
        => peerConnectionIdState.CurrentDestinationConnectionId.IsEmpty
            ? handshakeFlowCoordinator.DestinationConnectionId
            : peerConnectionIdState.CurrentDestinationConnectionId;

    internal ReadOnlyMemory<byte> CurrentHandshakeSourceConnectionId
        => handshakeFlowCoordinator.SourceConnectionId;

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

    internal bool TryConfigureRetryInitialPacketProtection(ReadOnlySpan<byte> retrySelectedDestinationConnectionId)
    {
        if (!QuicInitialPacketProtection.TryCreate(
            tlsState.Role,
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

    internal bool TryConfigureLocalApplicationProtocols(IReadOnlyList<SslApplicationProtocol> applicationProtocols)
    {
        return tlsBridgeDriver.TryConfigureLocalApplicationProtocols(applicationProtocols);
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
        highestConnectionIdIssuedToPeer = 0;
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
}
