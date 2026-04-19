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
        stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);

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
        if (phase is not (QuicConnectionPhase.Establishing or QuicConnectionPhase.Active)
            || activePath is null)
        {
            return false;
        }

        if (!TrySelectRecoveryTimer(nowTicks, out _, out QuicPacketNumberSpace selectedPacketNumberSpace))
        {
            return false;
        }

        bool sentProbe = TrySendRecoveryProbes(selectedPacketNumberSpace, nowTicks, ref effects);

        if (!sentProbe)
        {
            return false;
        }

        recoveryController.RecordProbeTimeoutExpired();
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool TrySelectRecoveryTimer(
        long nowTicks,
        out ulong selectedRecoveryTimerMicros,
        out QuicPacketNumberSpace selectedPacketNumberSpace)
    {
        ulong nowMicros = GetElapsedMicros(nowTicks);
        ulong maxAckDelayMicros = tlsState.PeerTransportParameters?.MaxAckDelay ?? 0;
        bool handshakeConfirmed = peerHandshakeTranscriptCompleted;
        bool serverAtAntiAmplificationLimit = tlsState.Role == QuicTlsRole.Server
            && (activePath is null
                || (!activePath.Value.AmplificationState.IsAddressValidated
                    && activePath.Value.AmplificationState.RemainingSendBudget == 0));
        bool peerAddressValidationComplete = transportFlags.HasFlag(QuicConnectionTransportState.PeerAddressValidated);

        return recoveryController.TrySelectLossDetectionTimer(
            nowMicros,
            maxAckDelayMicros,
            handshakeConfirmed,
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
        return selectedPacketNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => TryFlushInitialPackets(ref effects)
                || TryFlushHandshakePackets(ref effects)
                || FlushPendingApplicationSends(nowTicks, probePacket: true, ref effects)
                || TrySendRecoveryPingProbe(ref effects),
            QuicPacketNumberSpace.Handshake => TryFlushHandshakePackets(ref effects)
                || TryFlushInitialPackets(ref effects)
                || FlushPendingApplicationSends(nowTicks, probePacket: true, ref effects)
                || TrySendRecoveryPingProbe(ref effects),
            QuicPacketNumberSpace.ApplicationData => FlushPendingApplicationSends(nowTicks, probePacket: true, ref effects)
                || TryFlushHandshakePackets(ref effects)
                || TryFlushInitialPackets(ref effects)
                || TrySendRecoveryPingProbe(ref effects),
            _ => false,
        };
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
        if (!handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            applicationPayload[..bytesWritten],
            tlsState.OneRttProtectPacketProtectionMaterial!.Value,
            tlsState.CurrentOneRttKeyPhase == 1,
            out ulong packetNumber,
            out byte[] protectedPacket))
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

        if (idleTimeoutState is not null
            && idleTimeoutState.EffectiveIdleTimeoutMicros == effectiveIdleTimeoutMicros)
        {
            return false;
        }

        idleTimeoutState = new QuicIdleTimeoutState(effectiveIdleTimeoutMicros);
        idleTimeoutState.RecordPeerPacketProcessed(GetElapsedMicros(nowTicks));
        return true;
    }
}
