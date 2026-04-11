using System.Diagnostics;
using System.Net.Security;
using System.Text;
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
    private const int HandshakeEgressChunkBytes = QuicVersionNegotiation.Version1MinimumDatagramPayloadSize;

    private readonly IMonotonicClock clock;
    private readonly QuicConnectionSendRuntime sendRuntime;
    private readonly QuicConnectionStreamRegistry streamRegistry;
    private readonly Channel<QuicConnectionEvent> inbox;
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> candidatePaths = [];
    private readonly Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> recentlyValidatedPaths = [];
    private readonly Dictionary<ulong, byte[]> statelessResetTokensByConnectionId = [];
    private readonly long timeOriginTicks;
    private readonly QuicHandshakeFlowCoordinator handshakeFlowCoordinator;
    private readonly QuicTransportTlsBridgeState tlsState;
    private readonly QuicTlsTransportBridgeDriver tlsBridgeDriver;
    private QuicInitialPacketProtection? initialPacketProtection;
    private QuicConnectionPathIdentity? bootstrapOutboundPathIdentity;

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
    private long? terminalEndTicks;
    private long lastTransitionTicks;
    private ulong transitionSequence;

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
        RemoteCertificateValidationCallback? remoteCertificateValidationCallback = null,
        QuicTlsRole tlsRole = QuicTlsRole.Client)
    {
        this.clock = clock ?? new MonotonicClock();
        timeOriginTicks = this.clock.Ticks;
        sendRuntime = new QuicConnectionSendRuntime();
        streamRegistry = new QuicConnectionStreamRegistry(bookkeeping);
        handshakeFlowCoordinator = new QuicHandshakeFlowCoordinator();
        tlsState = new QuicTransportTlsBridgeState(tlsRole);
        tlsBridgeDriver = new QuicTlsTransportBridgeDriver(
            tlsRole,
            tlsState,
            localHandshakePrivateKey,
            pinnedPeerLeafCertificateSha256,
            localServerLeafCertificateDer,
            localServerLeafSigningPrivateKey,
            remoteCertificateValidationCallback);
        inbox = Channel.CreateUnbounded<QuicConnectionEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
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
        ReadOnlyMemory<byte> signingPrivateKey)
    {
        return tlsBridgeDriver.TryConfigureServerAuthenticationMaterial(certificateDer, signingPrivateKey);
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
        return TryPostEvent(localApiEvent);
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
            QuicConnectionHandshakeBootstrapRequestedEvent handshakeBootstrapRequestedEvent
                => HandleHandshakeBootstrapRequested(handshakeBootstrapRequestedEvent, nowTicks, ref effects),
            QuicConnectionTransportParametersCommittedEvent transportParametersCommittedEvent
                => ApplyTransportParameters(transportParametersCommittedEvent, nowTicks, ref effects),
            QuicConnectionTlsStateUpdatedEvent tlsStateUpdatedEvent
                => HandleTlsStateUpdated(tlsStateUpdatedEvent, nowTicks, ref effects),
            QuicConnectionCryptoFrameReceivedEvent cryptoFrameReceivedEvent
                => HandleCryptoFrameReceived(cryptoFrameReceivedEvent, nowTicks, ref effects),
            QuicConnectionPacketReceivedEvent packetReceivedEvent
                => HandlePacketReceived(packetReceivedEvent, nowTicks, ref effects),
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

        inbox.Writer.TryComplete();

        Task? processing = processingTask;
        if (processing is not null)
        {
            await processing.ConfigureAwait(false);
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

        IReadOnlyList<QuicTlsStateUpdate> updates = tlsBridgeDriver.StartHandshake(localTransportParameters);
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
                stateChanged |= TryFlushInitialPackets(ref effects);
                stateChanged |= TryFlushHandshakePackets(ref effects);
                break;
        }

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

    private bool TryHandleInitialPacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        ReadOnlySpan<byte> datagram = packetReceivedEvent.Datagram.Span;
        if (!QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Initial
            || initialPacketProtection is null
            || !handshakeFlowCoordinator.TryOpenInitialPacket(
                datagram,
                initialPacketProtection,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
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

        return TryProcessHandshakePacketPayload(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            QuicTlsEncryptionLevel.Initial,
            nowTicks,
            ref effects);
    }

    private bool TryHandleHandshakePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        ReadOnlySpan<byte> datagram = packetReceivedEvent.Datagram.Span;
        if (!QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Handshake
            || !tlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial packetProtectionMaterial)
            || !handshakeFlowCoordinator.TryOpenHandshakePacket(
                datagram,
                packetProtectionMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
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

    private bool TryFlushInitialPackets(ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || tlsState.InitialEgressCryptoBuffer.BufferedBytes <= 0
            || initialPacketProtection is null
            || !TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity))
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
                    out protectedPacket);
            }
            else
            {
                builtProtectedPacket = handshakeFlowCoordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
                    cryptoChunk[..cryptoBytesWritten],
                    cryptoOffset,
                    initialPacketProtection,
                    out protectedPacket);
            }

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

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
            tlsState.InitialEgressCryptoBuffer.DiscardFutureFrames();
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

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                protectedPacket));
            stateChanged = true;
        }

        return stateChanged;
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

        QuicConnectionTransportState committedTransportFlags = QuicConnectionTransportState.PeerTransportParametersCommitted;
        if (peerTransportParameters.DisableActiveMigration)
        {
            committedTransportFlags |= QuicConnectionTransportState.DisableActiveMigration;
        }

        return ApplyTransportParameters(
            new QuicConnectionTransportParametersCommittedEvent(
                ObservedAtTicks: nowTicks,
                TransportFlags: committedTransportFlags,
                PeerMaxIdleTimeoutMicros: peerTransportParameters.MaxIdleTimeout),
            nowTicks,
            ref effects);
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

    private bool HandlePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (SendingMode != QuicConnectionSendingMode.Ordinary)
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

        stateChanged |= TryFlushHandshakePackets(ref effects);

        if (stateChanged)
        {
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
        if (CanPromoteActivePathMigration()
            && TryPromoteValidatedCandidatePath(pathValidationSucceededEvent.PathIdentity, nowTicks, ref effects))
        {
            stateChanged = true;
        }

        UpdatePeerAddressValidationFlag();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        stateChanged |= TryFlushHandshakePackets(ref effects);
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
            AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(new QuicDiagnosticEvent(
                "connection.runtime.path",
                "validated-paths-exhausted",
                $"No validated paths remain after path validation failed for {pathValidationFailedEvent.PathIdentity.RemoteAddress}.",
                QuicDiagnosticSeverity.Warning)));
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
        List<QuicConnectionPathIdentity>? expiredPathIdentities = null;

        foreach (KeyValuePair<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> entry in candidatePaths)
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
                Validation = candidatePath.Validation with
                {
                    IsAbandoned = true,
                    ValidationDeadlineTicks = null,
                },
                LastActivityTicks = nowTicks,
            };
            candidatePaths[entry.Key] = candidatePath;
            (expiredPathIdentities ??= []).Add(entry.Key);
            stateChanged = true;
        }

        if (expiredPathIdentities is not null)
        {
            foreach (QuicConnectionPathIdentity expiredPathIdentity in expiredPathIdentities)
            {
                if (activePath is not null
                    && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, expiredPathIdentity))
                {
                    if (CanPromoteActivePathMigration()
                        && TryPromoteFallbackValidatedPath(nowTicks, ref effects))
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
            }
        }

        if (stateChanged && !HasValidatedPath)
        {
            AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(new QuicDiagnosticEvent(
                "connection.runtime.path",
                "path-validation-timer-exhausted",
                "No validated paths remain after a path-validation timer expired.",
                QuicDiagnosticSeverity.Warning)));
        }

        UpdatePeerAddressValidationFlag();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
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

        EnterTerminalPhase(
            QuicConnectionPhase.Draining,
            QuicConnectionCloseOrigin.Remote,
            connectionCloseFrameReceivedEvent.Close,
            nowTicks,
            preserveTerminalEndTicks: phase == QuicConnectionPhase.Closing);

        AppendTerminalEffects(ref effects, emitClosePacket: false);
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
        AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(new QuicDiagnosticEvent(
            "connection.runtime.lifecycle",
            "accepted-stateless-reset",
            $"Accepted a stateless reset on {acceptedStatelessResetEvent.PathIdentity.RemoteAddress} for connection ID {acceptedStatelessResetEvent.ConnectionId}.",
            QuicDiagnosticSeverity.Info)));

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
        AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(new QuicDiagnosticEvent(
            "connection.runtime.path",
            "address-change-classified",
            $"Packet from {pathIdentity.RemoteAddress} classified as {classification}.",
            QuicDiagnosticSeverity.Info)));

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
            AppendEffect(ref effects, new QuicConnectionEmitDiagnosticEffect(new QuicDiagnosticEvent(
                "connection.runtime.path",
                "candidate-path-budget-exhausted",
                $"Packet from {pathIdentity.RemoteAddress} classified as {QuicConnectionPathClassification.NoiseOrAttack} because the candidate-path budget is exhausted.",
                QuicDiagnosticSeverity.Warning)));
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

        if (activePathChanged && !CanPromoteActivePathMigration())
        {
            return false;
        }

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
                RestoreSavedState: candidatePath.SavedRecoverySnapshot.HasValue));
        }

        return true;
    }

    private bool TryPromoteFallbackValidatedPath(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
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
            RestoreSavedState: bestCandidate.Value.SavedRecoverySnapshot.HasValue));
        return true;
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

        return !transportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration);
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

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(terminalState.Value.Close);
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

        long? closeDueTicks = phase == QuicConnectionPhase.Closing ? terminalEndTicks : null;
        long? drainDueTicks = phase == QuicConnectionPhase.Draining ? terminalEndTicks : null;

        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, idleDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, closeDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.DrainLifetime, drainDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.PathValidation, pathValidationDueTicks));
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
