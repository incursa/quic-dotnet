namespace Incursa.Quic;

// Packet dispatch, timer dispatch, connection-id events, and close/idle transitions.
internal sealed partial class QuicConnectionRuntime
{
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
            stateChanged = HandleAddressChangePacket(
                packetReceivedEvent.PathIdentity,
                payloadBytes,
                nowTicks,
                ShouldDeferTrustedPathReusePromotion(packetReceivedEvent.PathIdentity, packetReceivedEvent.Datagram.Span),
                ref effects);
        }

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordPeerPacketProcessed(GetElapsedMicros(nowTicks));
            stateChanged = true;
        }

        if (phase == QuicConnectionPhase.Closing)
        {
            if (terminalState is QuicConnectionTerminalState terminalStateValue)
            {
                AppendConnectionClosePacket(ref effects, terminalStateValue.Close);
            }
        }
        else
        {
            stateChanged |= TryHandleReceivedPacketDatagram(packetReceivedEvent, nowTicks, ref effects);
        }

        stateChanged |= TryFlushHandshakePackets(ref effects);
        stateChanged |= TryFlushHandshakeDonePacket(ref effects);
        stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);

        if (stateChanged)
        {
            hasSuccessfullyProcessedAnotherPacket = true;
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        }

        return stateChanged;
    }

    private bool TryHandleReceivedPacketDatagram(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool stateChanged = false;
        bool processedAnyPacket = false;
        int packetOffset = 0;

        while (packetOffset < packetReceivedEvent.Datagram.Length)
        {
            ReadOnlyMemory<byte> remainingDatagram = packetReceivedEvent.Datagram[packetOffset..];
            if (!QuicPacketParser.TryGetPacketLength(remainingDatagram.Span, out int packetLength)
                || packetLength <= 0)
            {
                return processedAnyPacket && stateChanged;
            }

            QuicConnectionPacketReceivedEvent packetEvent = packetReceivedEvent with
            {
                Datagram = remainingDatagram[..packetLength],
            };

            processedAnyPacket = true;

            switch (phase)
            {
                case QuicConnectionPhase.Establishing:
                    stateChanged |= TryHandleInitialPacketReceived(packetEvent, nowTicks, ref effects);
                    stateChanged |= TryHandleHandshakePacketReceived(packetEvent, nowTicks, ref effects);
                    // The peer can legally send protected 1-RTT packets before the runtime flips to the
                    // fully active phase, so the establishing path cannot blanket-drop short-header ingress.
                    stateChanged |= TryHandleApplicationPacketReceived(packetEvent, nowTicks, ref effects);
                    break;

                case QuicConnectionPhase.Active:
                    stateChanged |= TryHandleApplicationPacketReceived(packetEvent, nowTicks, ref effects);
                    break;

                case QuicConnectionPhase.Closing:
                    if (terminalState is QuicConnectionTerminalState terminalStateValue)
                    {
                        AppendConnectionClosePacket(ref effects, terminalStateValue.Close);
                    }

                    return stateChanged;

                default:
                    return stateChanged;
            }

            packetOffset += packetLength;
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

        AppendRecentlyValidatedPath(
            candidatePath.Identity,
            nowTicks,
            candidatePath.SavedRecoverySnapshot,
            candidatePath.AmplificationState,
            candidatePath.MaximumDatagramSizeState);
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
        stateChanged |= TryQueueNewTokenEmission(pathValidationSucceededEvent.PathIdentity, nowTicks, ref effects);
        stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);
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
                return false;
            }

            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.PathValidationFailedNoValidatedPathsRemain(pathValidationFailedEvent.PathIdentity));
            }

            UpdatePeerAddressValidationFlag();
            return DiscardConnection(nowTicks, QuicConnectionCloseOrigin.Remote, default, ref effects);
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

            UpdatePeerAddressValidationFlag();
            return DiscardConnection(nowTicks, QuicConnectionCloseOrigin.Remote, default, ref effects);
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
        if (connectionIdIssuedEvent.ConnectionId > highestConnectionIdIssuedToPeer)
        {
            highestConnectionIdIssuedToPeer = connectionIdIssuedEvent.ConnectionId;
        }

        AppendEffect(ref effects, new QuicConnectionRegisterStatelessResetTokenEffect(connectionIdIssuedEvent.ConnectionId, token));
        return true;
    }

    private bool HandleConnectionIdRetired(
        QuicConnectionConnectionIdRetiredEvent connectionIdRetiredEvent,
        ref List<QuicConnectionEffect>? effects)
    {
        if (!statelessResetTokensByConnectionId.Remove(connectionIdRetiredEvent.ConnectionId, out _))
        {
            return false;
        }

        AppendEffect(ref effects, new QuicConnectionRetireStatelessResetTokenEffect(connectionIdRetiredEvent.ConnectionId));

        // Token retirement is locally actionable even when no path is available to emit RETIRE_CONNECTION_ID yet.
        bool stateChanged = true;
        stateChanged |= TrySendRetireConnectionIdFrame(connectionIdRetiredEvent.ConnectionId, ref effects);
        return stateChanged;
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
            QuicConnectionTimerKind.Recovery => timerState.Recovery,
            QuicConnectionTimerKind.KeyUpdateRetention => timerState.KeyUpdateRetention,
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
                if (!FlushPendingApplicationSends(nowTicks, ref effects))
                {
                    return false;
                }

                AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
                return true;
            case QuicConnectionTimerKind.Recovery:
                return HandleRecoveryTimerExpired(nowTicks, ref effects);
            case QuicConnectionTimerKind.KeyUpdateRetention:
                return HandleKeyUpdateRetentionTimerExpired(ref effects);
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

    private bool HandleRecoveryTimerExpired(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (phase is not (QuicConnectionPhase.Establishing or QuicConnectionPhase.Active))
        {
            return false;
        }

        if (!TrySelectRecoveryTimer(nowTicks, out _, out QuicPacketNumberSpace selectedPacketNumberSpace))
        {
            return false;
        }

        bool stateChanged = TryRegisterDetectedLosses(nowTicks);
        bool sentProbe = TrySendRecoveryProbes(selectedPacketNumberSpace, nowTicks, ref effects);

        if (!sentProbe)
        {
            if (stateChanged)
            {
                AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
            }

            return stateChanged;
        }

        recoveryController.RecordProbeTimeoutExpired();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool HandleKeyUpdateRetentionTimerExpired(ref List<QuicConnectionEffect>? effects)
    {
        if (phase is not (QuicConnectionPhase.Establishing or QuicConnectionPhase.Active))
        {
            return false;
        }

        return TryDiscardExpiredRetainedOldOneRttKeyMaterial(ref effects);
    }

    private bool TrySelectRecoveryTimer(
        long nowTicks,
        out ulong selectedRecoveryTimerMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        ulong nowMicros = GetElapsedMicros(nowTicks);
        ulong maxAckDelayMicros = tlsState.PeerTransportParameters?.MaxAckDelay ?? 0;
        bool isHandshakeConfirmed = HandshakeConfirmed;
        bool serverAtAntiAmplificationLimit = tlsState.Role == QuicTlsRole.Server
            && (activePath is null
                || (!activePath.Value.AmplificationState.IsAddressValidated
                    && activePath.Value.AmplificationState.RemainingSendBudget == 0));
        bool peerAddressValidationComplete = transportFlags.HasFlag(QuicConnectionTransportState.PeerAddressValidated);

        return recoveryController.TrySelectLossDetectionTimer(
            nowMicros,
            maxAckDelayMicros,
            isHandshakeConfirmed,
            serverAtAntiAmplificationLimit,
            peerAddressValidationComplete,
            tlsState.HandshakeKeysAvailable,
            out selectedRecoveryTimerMicros,
            out selectedPacketNumberSpace);
    }

    private bool TrySendRecoveryProbes(
        QuicPacketNumberSpace selectedPacketNumberSpace,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool sentProbe;
        switch (selectedPacketNumberSpace)
        {
            case QuicPacketNumberSpace.Initial:
                sentProbe = TrySendRecoveryProbeSequence(
                    QuicPacketNumberSpace.Initial,
                    QuicPacketNumberSpace.Handshake,
                    QuicPacketNumberSpace.ApplicationData,
                    nowTicks,
                    ref effects);
                break;
            case QuicPacketNumberSpace.Handshake:
                sentProbe = TrySendRecoveryProbeSequence(
                    QuicPacketNumberSpace.Handshake,
                    QuicPacketNumberSpace.Initial,
                    QuicPacketNumberSpace.ApplicationData,
                    nowTicks,
                    ref effects);
                break;
            case QuicPacketNumberSpace.ApplicationData:
                sentProbe = TrySendRecoveryProbeSequence(
                    QuicPacketNumberSpace.ApplicationData,
                    QuicPacketNumberSpace.Handshake,
                    QuicPacketNumberSpace.Initial,
                    nowTicks,
                    ref effects);
                break;
            default:
                return false;
        }

        if (sentProbe)
        {
            return true;
        }

        return selectedPacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && TrySendRecoveryPingProbe(ref effects);
    }

    private bool TrySendRecoveryProbeDatagram(
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => TryFlushInitialPackets(
                    ref effects,
                    probePacket: true,
                    maximumDatagrams: 1)
                || TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.Initial,
                    nowTicks,
                    probePacket: true,
                    ref effects)
                || TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Initial)
                && TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.Initial,
                    nowTicks,
                    probePacket: true,
                    ref effects),
            QuicPacketNumberSpace.Handshake => TryFlushHandshakePackets(
                    ref effects,
                    probePacket: true,
                    maximumDatagrams: 1)
                || TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.Handshake,
                    nowTicks,
                    probePacket: true,
                    ref effects)
                || TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Handshake)
                && TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.Handshake,
                    nowTicks,
                    probePacket: true,
                    ref effects),
            QuicPacketNumberSpace.ApplicationData => TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.ApplicationData,
                    nowTicks,
                    probePacket: true,
                    ref effects)
                || FlushPendingApplicationSends(nowTicks, probePacket: true, ref effects)
                || TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.ApplicationData)
                && TryFlushPendingRetransmissions(
                    QuicPacketNumberSpace.ApplicationData,
                    nowTicks,
                    probePacket: true,
                    ref effects),
            _ => false,
        };
    }

    private bool TryPromoteOutstandingProbePacket(QuicPacketNumberSpace packetNumberSpace)
    {
        bool preferStreamData = packetNumberSpace == QuicPacketNumberSpace.ApplicationData;
        bool preferCryptoData = packetNumberSpace is QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake;
        QuicConnectionSentPacketKey? candidateKey = null;
        bool candidateIsProbePacket = false;
        bool candidateHasPreferredPayload = false;
        bool candidateCarriesStreamData = false;
        bool candidateClosesStream = false;
        ulong candidateStreamEndOffset = 0;
        bool candidateHasCryptoPriority = false;
        ulong candidateCryptoEndOffset = 0;

        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> entry in sendRuntime.SentPackets)
        {
            if (entry.Key.PacketNumberSpace != packetNumberSpace)
            {
                continue;
            }

            QuicConnectionSentPacket packet = entry.Value;
            if (!packet.AckEliciting
                || packet.AckOnlyPacket
                || !packet.Retransmittable
                || packet.PacketBytes.IsEmpty)
            {
                continue;
            }

            bool entryIsProbePacket = packet.ProbePacket;
            bool entryHasCryptoPriority = false;
            ulong entryCryptoEndOffset = 0;
            if (preferCryptoData)
            {
                entryHasCryptoPriority = TryGetCryptoProbeSelectionPriority(
                    packet,
                    out entryCryptoEndOffset);
            }

            bool entryHasPreferredPayload = preferCryptoData
                ? entryHasCryptoPriority
                : !preferStreamData
                || packet.StreamIds is { Length: > 0 };
            bool entryCarriesStreamData = false;
            bool entryClosesStream = false;
            ulong entryStreamEndOffset = 0;
            if (preferStreamData
                && entryHasPreferredPayload)
            {
                _ = TryGetApplicationProbeSelectionPriority(
                    packet,
                    out entryCarriesStreamData,
                    out entryClosesStream,
                    out entryStreamEndOffset);
            }

            if (candidateKey is not null)
            {
                if (preferCryptoData)
                {
                    if (!IsPreferredOutstandingCryptoProbeCandidate(
                            candidateHasCryptoPriority,
                            candidateCryptoEndOffset,
                            candidateIsProbePacket,
                            candidateKey.Value.PacketNumber,
                            entryHasCryptoPriority,
                            entryCryptoEndOffset,
                            entryIsProbePacket,
                            entry.Key.PacketNumber))
                    {
                        continue;
                    }
                }
                else
                {
                    bool samePayloadClass = candidateHasPreferredPayload == entryHasPreferredPayload;
                    bool preferEntryForFreshness = candidateIsProbePacket
                        && !entryIsProbePacket
                        && samePayloadClass;
                    if (!candidateIsProbePacket && entryIsProbePacket && samePayloadClass)
                    {
                        continue;
                    }

                    if (!preferEntryForFreshness)
                    {
                        if (candidateHasPreferredPayload && !entryHasPreferredPayload)
                        {
                            continue;
                        }

                        if (!candidateHasPreferredPayload && entryHasPreferredPayload)
                        {
                            // Prefer application packets that actually repair stream progress.
                        }
                        else if (preferStreamData)
                        {
                            if (!IsPreferredApplicationProbeCandidate(
                                    candidateCarriesStreamData,
                                    candidateClosesStream,
                                    candidateStreamEndOffset,
                                    candidateKey.Value.PacketNumber,
                                    entryCarriesStreamData,
                                    entryClosesStream,
                                    entryStreamEndOffset,
                                    entry.Key.PacketNumber))
                            {
                                continue;
                            }
                        }
                        else if (entry.Key.PacketNumber >= candidateKey.Value.PacketNumber)
                        {
                            continue;
                        }
                    }
                }
            }

            candidateKey = entry.Key;
            candidateIsProbePacket = entryIsProbePacket;
            candidateHasPreferredPayload = entryHasPreferredPayload;
            candidateCarriesStreamData = entryCarriesStreamData;
            candidateClosesStream = entryClosesStream;
            candidateStreamEndOffset = entryStreamEndOffset;
            candidateHasCryptoPriority = entryHasCryptoPriority;
            candidateCryptoEndOffset = entryCryptoEndOffset;
        }

        if (candidateKey is null)
        {
            return false;
        }

        return sendRuntime.TryRegisterLoss(
            candidateKey.Value.PacketNumberSpace,
            candidateKey.Value.PacketNumber,
            handshakeConfirmed: HandshakeConfirmed,
            scheduleRetransmission: true);
    }

    private static bool IsPreferredOutstandingCryptoProbeCandidate(
        bool currentHasCryptoPriority,
        ulong currentCryptoEndOffset,
        bool currentProbePacket,
        ulong currentPacketNumber,
        bool candidateHasCryptoPriority,
        ulong candidateCryptoEndOffset,
        bool candidateProbePacket,
        ulong candidatePacketNumber)
    {
        if (currentHasCryptoPriority != candidateHasCryptoPriority)
        {
            return candidateHasCryptoPriority;
        }

        if (currentHasCryptoPriority)
        {
            if (currentCryptoEndOffset != candidateCryptoEndOffset)
            {
                return candidateCryptoEndOffset > currentCryptoEndOffset;
            }

            if (currentProbePacket != candidateProbePacket)
            {
                return !candidateProbePacket;
            }

            return candidatePacketNumber > currentPacketNumber;
        }

        if (currentProbePacket != candidateProbePacket)
        {
            return !candidateProbePacket;
        }

        return candidatePacketNumber < currentPacketNumber;
    }

    private bool TryGetApplicationProbeSelectionPriority(
        QuicConnectionSentPacket packet,
        out bool carriesStreamData,
        out bool closesStream,
        out ulong streamEndOffset)
    {
        if (!packet.PlaintextPayload.IsEmpty)
        {
            return TryParseApplicationProbeSelectionPriority(
                packet.PlaintextPayload.Span,
                out carriesStreamData,
                out closesStream,
                out streamEndOffset);
        }

        return TryGetApplicationProbeSelectionPriority(
            packet.PacketBytes,
            out carriesStreamData,
            out closesStream,
            out streamEndOffset);
    }

    private bool TryGetApplicationProbeSelectionPriority(
        QuicConnectionRetransmissionPlan retransmission,
        out bool carriesStreamData,
        out bool closesStream,
        out ulong streamEndOffset)
    {
        if (!retransmission.PlaintextPayload.IsEmpty)
        {
            return TryParseApplicationProbeSelectionPriority(
                retransmission.PlaintextPayload.Span,
                out carriesStreamData,
                out closesStream,
                out streamEndOffset);
        }

        return TryGetApplicationProbeSelectionPriority(
            retransmission.PacketBytes,
            out carriesStreamData,
            out closesStream,
            out streamEndOffset);
    }

    private bool TryGetApplicationProbeSelectionPriority(
        ReadOnlyMemory<byte> packetBytes,
        out bool carriesStreamData,
        out bool closesStream,
        out ulong streamEndOffset)
    {
        carriesStreamData = false;
        closesStream = false;
        streamEndOffset = 0;

        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        QuicHandshakeFlowCoordinator probeSelectionCoordinator = new(CurrentPeerDestinationConnectionId);
        QuicBufferLease openedPacket = default;
        try
        {
            if (!probeSelectionCoordinator.TryOpenProtectedApplicationDataPacket(
                    packetBytes.Span,
                    tlsState.OneRttProtectPacketProtectionMaterial.Value,
                    out openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out _))
            {
                return false;
            }

            return TryParseApplicationProbeSelectionPriority(
                openedPacket.Span.Slice(payloadOffset, payloadLength),
                out carriesStreamData,
                out closesStream,
                out streamEndOffset);
        }
        finally
        {
            openedPacket.Dispose();
        }
    }

    private static bool TryParseApplicationProbeSelectionPriority(
        ReadOnlySpan<byte> payload,
        out bool carriesStreamData,
        out bool closesStream,
        out ulong streamEndOffset)
    {
        carriesStreamData = false;
        closesStream = false;
        streamEndOffset = 0;

        bool parsedStreamFrame = false;
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];
            int paddingLength = 0;
            while (paddingLength < remaining.Length
                && remaining[paddingLength] == 0)
            {
                paddingLength++;
            }

            if (paddingLength > 0)
            {
                offset += paddingLength;
                continue;
            }

            if (QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                parsedStreamFrame = true;
                carriesStreamData |= streamFrame.StreamDataLength > 0;
                closesStream |= streamFrame.IsFin;
                ulong streamFrameEndOffset = streamFrame.Offset + (ulong)streamFrame.StreamDataLength;
                if (streamFrameEndOffset > streamEndOffset)
                {
                    streamEndOffset = streamFrameEndOffset;
                }

                offset += streamFrame.ConsumedLength;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                offset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed))
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseCryptoFrame(remaining, out _, out int cryptoBytesConsumed))
            {
                offset += cryptoBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseNewTokenFrame(remaining, out _, out int newTokenBytesConsumed))
            {
                offset += newTokenBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseHandshakeDoneFrame(remaining, out _, out int handshakeDoneBytesConsumed))
            {
                offset += handshakeDoneBytesConsumed;
                continue;
            }

            break;
        }

        return parsedStreamFrame;
    }

    private static bool IsPreferredApplicationProbeCandidate(
        bool currentCarriesStreamData,
        bool currentClosesStream,
        ulong currentStreamEndOffset,
        ulong currentPacketNumber,
        bool candidateCarriesStreamData,
        bool candidateClosesStream,
        ulong candidateStreamEndOffset,
        ulong candidatePacketNumber)
    {
        if (currentCarriesStreamData != candidateCarriesStreamData)
        {
            return candidateCarriesStreamData;
        }

        if (currentClosesStream != candidateClosesStream)
        {
            return candidateClosesStream;
        }

        if (currentStreamEndOffset != candidateStreamEndOffset)
        {
            return candidateStreamEndOffset > currentStreamEndOffset;
        }

        return candidatePacketNumber > currentPacketNumber;
    }

    private bool TrySendRecoveryProbeSequence(
        QuicPacketNumberSpace firstPacketNumberSpace,
        QuicPacketNumberSpace secondPacketNumberSpace,
        QuicPacketNumberSpace thirdPacketNumberSpace,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (TrySendCoalescedCryptoRecoveryProbeDatagram(
            firstPacketNumberSpace,
            secondPacketNumberSpace,
            ref effects))
        {
            _ = TrySendAdditionalRecoveryProbeDatagram(
                firstPacketNumberSpace,
                secondPacketNumberSpace,
                thirdPacketNumberSpace,
                nowTicks,
                initialAndHandshakeAlreadyCoalesced: true,
                ref effects);
            return true;
        }

        if (!TrySendRecoveryProbeDatagram(firstPacketNumberSpace, nowTicks, ref effects))
        {
            return false;
        }

        _ = TrySendAdditionalRecoveryProbeDatagram(
            firstPacketNumberSpace,
            secondPacketNumberSpace,
            thirdPacketNumberSpace,
            nowTicks,
            initialAndHandshakeAlreadyCoalesced: false,
            ref effects);
        return true;
    }

    private bool TrySendAdditionalRecoveryProbeDatagram(
        QuicPacketNumberSpace firstPacketNumberSpace,
        QuicPacketNumberSpace secondPacketNumberSpace,
        QuicPacketNumberSpace thirdPacketNumberSpace,
        long nowTicks,
        bool initialAndHandshakeAlreadyCoalesced,
        ref List<QuicConnectionEffect>? effects)
    {
        if (initialAndHandshakeAlreadyCoalesced)
        {
            if (IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace)
                && thirdPacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
                    nowTicks,
                    ref effects))
            {
                return true;
            }

            return TrySendRecoveryProbeDatagram(thirdPacketNumberSpace, nowTicks, ref effects);
        }

        if (firstPacketNumberSpace == QuicPacketNumberSpace.Initial
            && secondPacketNumberSpace == QuicPacketNumberSpace.Handshake
            && thirdPacketNumberSpace == QuicPacketNumberSpace.ApplicationData)
        {
            return TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
                    nowTicks,
                    ref effects)
                || TrySendRecoveryProbeDatagram(secondPacketNumberSpace, nowTicks, ref effects)
                || TrySendRecoveryProbeDatagram(thirdPacketNumberSpace, nowTicks, ref effects)
                || TrySendRecoveryProbeDatagram(firstPacketNumberSpace, nowTicks, ref effects);
        }

        if (IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace)
            && thirdPacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && TrySendCoalescedHandshakeAndApplicationRecoveryProbeDatagram(
                nowTicks,
                ref effects))
        {
            return true;
        }

        if (IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace)
            && thirdPacketNumberSpace == QuicPacketNumberSpace.ApplicationData
            && TrySendRecoveryProbeDatagram(thirdPacketNumberSpace, nowTicks, ref effects))
        {
            return true;
        }

        if (IsInitialAndHandshakePair(firstPacketNumberSpace, secondPacketNumberSpace))
        {
            return TrySendRecoveryProbeDatagram(secondPacketNumberSpace, nowTicks, ref effects)
                || TrySendRecoveryProbeDatagram(firstPacketNumberSpace, nowTicks, ref effects);
        }

        return TrySendRecoveryProbeDatagram(firstPacketNumberSpace, nowTicks, ref effects);
    }

    private bool TrySendRecoveryPingProbe(ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null
            || !activePath.Value.MaximumDatagramSizeState.CanSendOrdinaryPackets
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
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

        QuicConnectionActivePathRecord currentPath = activePath.Value;
        if (!TryPrepareOneRttProtectionForAeadLimit(
                "The connection runtime could not protect the recovery PING probe packet.",
                ref effects,
                out _))
        {
            return false;
        }

        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload[..bytesWritten],
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            out ulong packetNumber,
            out byte[] protectedPacket))
        {
            return false;
        }

        if (!tlsState.TryRecordCurrentOneRttProtectionUse())
        {
            return false;
        }

        if (!currentPath.MaximumDatagramSizeState.CanSend((ulong)protectedPacket.Length))
        {
            return false;
        }

        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            protectedPacket.Length,
            out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        TrackApplicationPacket(packetNumber, protectedPacket, retransmittable: false, probePacket: true);
        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
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

        if (idleTimeoutState is not null)
        {
            return idleTimeoutState.TryUpdateEffectiveIdleTimeoutMicros(effectiveIdleTimeoutMicros);
        }

        idleTimeoutState = new QuicIdleTimeoutState(effectiveIdleTimeoutMicros);
        idleTimeoutState.RecordPeerPacketProcessed(GetElapsedMicros(nowTicks));
        return true;
    }
}
