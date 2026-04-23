namespace Incursa.Quic;

// TLS/bootstrap handling, packet ingress, and transport-parameter commits.
internal sealed partial class QuicConnectionRuntime
{
    private const int BitsPerByte = 8;
    private static readonly bool ApplicationReceiveDebugEnabled =
        string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DEBUG_APP_RX"),
            "1",
            StringComparison.Ordinal);

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
            bufferedEstablishmentHandshakePackets.Clear();

            if (phase == QuicConnectionPhase.Establishing)
            {
                phase = QuicConnectionPhase.Active;
            }

            // The supported client floor still uses transcript completion as the currently
            // available bootstrap-path validation proof point so the active path does not
            // remain stuck in bootstrap-only state once the peer handshake flight is proven.
            // Recovery-level handshake confirmation remains a separate client-side signal.
            if (QuicAddressValidation.PeerCompletedAddressValidation(
                    isServer: tlsState.Role == QuicTlsRole.Server,
                    handshakeAckReceived: false,
                    handshakeConfirmed: peerHandshakeTranscriptCompleted))
            {
                stateChanged |= TryMarkActivePathValidated(nowTicks);
            }

            if (TryPromoteValidatedCandidatePath(nowTicks, ref effects))
            {
                stateChanged = true;
            }

            stateChanged |= TryFlushHandshakeDonePacket(ref effects);
            stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);

            if (tlsState.Role == QuicTlsRole.Server)
            {
                stateChanged |= TryPublishTlsKeyDiscard(
                    QuicTlsEncryptionLevel.Initial,
                    nowTicks,
                    ref effects);
                stateChanged |= TryPublishTlsKeyDiscard(
                    QuicTlsEncryptionLevel.Handshake,
                    nowTicks,
                    ref effects);
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

        if (!TryConfigureRetryInitialPacketProtection(retryReceivedEvent.RetrySourceConnectionId.Span))
        {
            return false;
        }

        ResetRecoveryStateForRetry();
        retrySourceConnectionId = retryReceivedEvent.RetrySourceConnectionId.ToArray();
        retryToken = retryReceivedEvent.RetryToken.ToArray();
        observedPeerInitialSourceConnectionId = null;
        observedPeerInitialCryptoFrameData = null;
        bufferedEstablishmentHandshakePackets.Clear();
        retryBootstrapPendingReplay = true;
        hasSuccessfullyProcessedAnotherPacket = true;

        bool stateChanged = true;
        stateChanged |= TrySetHandshakeDestinationConnectionId(retryReceivedEvent.RetrySourceConnectionId.Span);
        EmitDiagnostic(ref effects, QuicDiagnostics.RetryReceived(retryReceivedEvent.Datagram.Span));
        stateChanged |= TryFlushInitialPackets(ref effects);
        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
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
                versionProfile.SelectedVersion,
                versionProfile.SupportedVersions.Span,
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

            case QuicTlsUpdateKind.ResumptionAttemptDispositionAvailable:
                if (tlsState.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Rejected)
                {
                    stateChanged |= HandleTlsKeyDiscard(QuicTlsEncryptionLevel.ZeroRtt, ref effects);
                }
                break;

            case QuicTlsUpdateKind.PeerEarlyDataDispositionAvailable:
                if (tlsState.PeerEarlyDataDisposition == QuicTlsEarlyDataDisposition.Rejected)
                {
                    stateChanged |= HandleTlsKeyDiscard(QuicTlsEncryptionLevel.ZeroRtt, ref effects);
                }
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
                stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);
                break;
        }

        stateChanged |= TryCaptureResumptionMasterSecret();
        if (stateChanged)
        {
            AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
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
            || packetNumberSpace != QuicPacketNumberSpace.Initial)
        {
            return false;
        }

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketReceived(packetReceivedEvent.PathIdentity, datagram));
        }

        if (initialPacketProtection is null
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

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        byte[]? acceptedPeerInitialSourceConnectionId = null;
        if (tlsState.Role == QuicTlsRole.Client
            && phase == QuicConnectionPhase.Establishing
            && !peerHandshakeTranscriptCompleted
            && QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out _,
                out _,
                out ReadOnlySpan<byte> initialSourceConnectionId,
                out _))
        {
            acceptedPeerInitialSourceConnectionId = initialSourceConnectionId.ToArray();
            bool hasOffsetZeroInitialCrypto = TryExtractOffsetZeroInitialCryptoFrameData(
                payload,
                out ReadOnlySpan<byte> initialCryptoFrameData);

            if (observedPeerInitialSourceConnectionId is null)
            {
                observedPeerInitialSourceConnectionId = initialSourceConnectionId.ToArray();
                _ = TrySetHandshakeDestinationConnectionId(initialSourceConnectionId);

                if (hasOffsetZeroInitialCrypto)
                {
                    observedPeerInitialCryptoFrameData = initialCryptoFrameData.ToArray();
                }
            }
            else if (hasOffsetZeroInitialCrypto)
            {
                bool differentInitialSourceConnectionId =
                    !observedPeerInitialSourceConnectionId.AsSpan().SequenceEqual(initialSourceConnectionId);

                if (differentInitialSourceConnectionId
                    && observedPeerInitialCryptoFrameData is not null
                    && !HasMatchingInitialCryptoPrefix(
                        observedPeerInitialCryptoFrameData,
                        initialCryptoFrameData))
                {
                    _ = TryResetClientPeerHandshakeAttempt(
                        initialSourceConnectionId,
                        initialCryptoFrameData);
                }
                else if (observedPeerInitialCryptoFrameData is null
                    || (HasMatchingInitialCryptoPrefix(
                            observedPeerInitialCryptoFrameData,
                            initialCryptoFrameData)
                        && initialCryptoFrameData.Length > observedPeerInitialCryptoFrameData.Length))
                {
                    observedPeerInitialCryptoFrameData = initialCryptoFrameData.ToArray();
                }
            }
        }

        bool processed = TryProcessHandshakePacketPayload(
            payload,
            QuicTlsEncryptionLevel.Initial,
            nowTicks,
            ref effects);
        if (processed
            && acceptedPeerInitialSourceConnectionId is not null)
        {
            processed |= TryReplayBufferedEstablishmentHandshakePackets(
                acceptedPeerInitialSourceConnectionId,
                nowTicks,
                ref effects);
        }

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketProcessingResult(processed));
        }

        return processed;
    }

    private bool TryResetClientPeerHandshakeAttempt(
        ReadOnlySpan<byte> replacementSourceConnectionId,
        ReadOnlySpan<byte> replacementInitialCryptoFrameData)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || peerHandshakeTranscriptCompleted
            || replacementSourceConnectionId.IsEmpty
            || replacementInitialCryptoFrameData.IsEmpty
            || !tlsBridgeDriver.TryResetClientPeerHandshakeAttempt())
        {
            return false;
        }

        ResetRecoveryStateForRetry();
        observedPeerInitialSourceConnectionId = replacementSourceConnectionId.ToArray();
        observedPeerInitialCryptoFrameData = replacementInitialCryptoFrameData.ToArray();
        return TrySetHandshakeDestinationConnectionId(replacementSourceConnectionId);
    }

    private static bool TryExtractOffsetZeroInitialCryptoFrameData(
        ReadOnlySpan<byte> payload,
        out ReadOnlySpan<byte> cryptoData)
    {
        cryptoData = default;

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

            if (QuicFrameCodec.TryParseAckFrame(remaining, out _, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    return false;
                }

                payloadOffset += ackBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed)
                || cryptoBytesConsumed <= 0)
            {
                return false;
            }

            if (cryptoFrame.Offset == 0 && !cryptoFrame.CryptoData.IsEmpty)
            {
                cryptoData = cryptoFrame.CryptoData;
                return true;
            }

            payloadOffset += cryptoBytesConsumed;
        }

        return false;
    }

    private static bool HasMatchingInitialCryptoPrefix(
        ReadOnlySpan<byte> observedInitialCryptoFrameData,
        ReadOnlySpan<byte> candidateInitialCryptoFrameData)
    {
        int sharedPrefixLength = Math.Min(
            observedInitialCryptoFrameData.Length,
            candidateInitialCryptoFrameData.Length);
        return sharedPrefixLength == 0
            || observedInitialCryptoFrameData[..sharedPrefixLength].SequenceEqual(
                candidateInitialCryptoFrameData[..sharedPrefixLength]);
    }

    private bool TryHandleHandshakePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return TryHandleHandshakePacketReceived(
            packetReceivedEvent,
            nowTicks,
            allowDeferredBuffering: true,
            ref effects);
    }

    private bool TryHandleHandshakePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        bool allowDeferredBuffering,
        ref List<QuicConnectionEffect>? effects)
    {
        ReadOnlySpan<byte> datagram = packetReceivedEvent.Datagram.Span;
        if (!QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Handshake)
        {
            return false;
        }

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketReceived(packetReceivedEvent.PathIdentity, datagram));
        }

        if (!tlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(
                    packetReceivedEvent.PathIdentity,
                    "missing-open-material",
                    datagram));
            }

            if (allowDeferredBuffering)
            {
                _ = TryBufferEstablishmentHandshakePacketForDeferredRetry(packetReceivedEvent);
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
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(
                    packetReceivedEvent.PathIdentity,
                    "decrypt-or-layout-failed",
                    datagram));
            }

            if (allowDeferredBuffering)
            {
                _ = TryBufferEstablishmentHandshakePacketForDeferredRetry(packetReceivedEvent);
            }

            return false;
        }

        bool processed = TryProcessHandshakePacketPayload(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            QuicTlsEncryptionLevel.Handshake,
            nowTicks,
            ref effects);
        if (processed)
        {
            processed |= TryPublishTlsKeyDiscard(
                QuicTlsEncryptionLevel.Initial,
                nowTicks,
                ref effects);
        }

        return processed;
    }

    private bool TryBufferEstablishmentHandshakePacketForDeferredRetry(
        QuicConnectionPacketReceivedEvent packetReceivedEvent)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || peerHandshakeTranscriptCompleted
            || !QuicPacketParsing.TryParseLongHeaderFields(
                packetReceivedEvent.Datagram.Span,
                out _,
                out _,
                out _,
                out ReadOnlySpan<byte> sourceConnectionId,
                out _)
            || sourceConnectionId.IsEmpty
            || (observedPeerInitialSourceConnectionId is not null
                && observedPeerInitialSourceConnectionId.AsSpan().SequenceEqual(sourceConnectionId)))
        {
            return false;
        }

        foreach (BufferedEstablishmentHandshakePacket bufferedPacket in bufferedEstablishmentHandshakePackets)
        {
            if (bufferedPacket.SourceConnectionId.AsSpan().SequenceEqual(sourceConnectionId)
                && bufferedPacket.Datagram.AsSpan().SequenceEqual(packetReceivedEvent.Datagram.Span))
            {
                return true;
            }
        }

        if (bufferedEstablishmentHandshakePackets.Count >= MaximumBufferedEstablishmentHandshakePackets)
        {
            bufferedEstablishmentHandshakePackets.RemoveAt(0);
        }

        bufferedEstablishmentHandshakePackets.Add(new BufferedEstablishmentHandshakePacket(
            packetReceivedEvent.PathIdentity,
            sourceConnectionId.ToArray(),
            packetReceivedEvent.Datagram.ToArray()));
        return true;
    }

    private bool TryReplayBufferedEstablishmentHandshakePackets(
        byte[] acceptedPeerInitialSourceConnectionId,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (acceptedPeerInitialSourceConnectionId.Length == 0
            || bufferedEstablishmentHandshakePackets.Count == 0)
        {
            return false;
        }

        List<BufferedEstablishmentHandshakePacket>? matchingPackets = null;
        for (int index = bufferedEstablishmentHandshakePackets.Count - 1; index >= 0; index--)
        {
            BufferedEstablishmentHandshakePacket bufferedPacket = bufferedEstablishmentHandshakePackets[index];
            if (!bufferedPacket.SourceConnectionId.AsSpan().SequenceEqual(acceptedPeerInitialSourceConnectionId))
            {
                continue;
            }

            matchingPackets ??= [];
            matchingPackets.Insert(0, bufferedPacket);
            bufferedEstablishmentHandshakePackets.RemoveAt(index);
        }

        if (matchingPackets is null)
        {
            return false;
        }

        bool stateChanged = false;
        foreach (BufferedEstablishmentHandshakePacket bufferedPacket in matchingPackets)
        {
            stateChanged |= TryHandleHandshakePacketReceived(
                new QuicConnectionPacketReceivedEvent(
                    nowTicks,
                    bufferedPacket.PathIdentity,
                    bufferedPacket.Datagram),
                nowTicks,
                allowDeferredBuffering: false,
                ref effects);
        }

        return stateChanged;
    }

    private bool TryProcessHandshakePacketPayload(
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        bool processedCryptoFrame = false;
        bool progressedTranscript = false;
        bool replayedDuplicateInitialCrypto = false;
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

            if (QuicFrameCodec.TryParseAckFrame(remaining, out QuicAckFrame ackFrame, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    return false;
                }

                QuicPacketNumberSpace packetNumberSpace = encryptionLevel switch
                {
                    QuicTlsEncryptionLevel.Initial => QuicPacketNumberSpace.Initial,
                    QuicTlsEncryptionLevel.Handshake => QuicPacketNumberSpace.Handshake,
                    _ => throw new InvalidOperationException($"Unsupported handshake packet encryption level {encryptionLevel}."),
                };

                stateChanged |= HandleAckFrame(
                    packetNumberSpace,
                    ackFrame,
                    nowTicks,
                    receivedInRetainedOldOneRttPacket: false,
                    ref effects);
                payloadOffset += ackBytesConsumed;
                continue;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                return false;
            }

            processedCryptoFrame = true;
            if (IsDuplicateServerInitialCryptoFrame(encryptionLevel, cryptoFrame))
            {
                if (!replayedDuplicateInitialCrypto)
                {
                    replayedDuplicateInitialCrypto = TryReplayOutstandingCryptoAfterDuplicateInitialIngress(
                        encryptionLevel,
                        nowTicks,
                        ref effects);
                    stateChanged |= replayedDuplicateInitialCrypto;
                }

                payloadOffset += bytesConsumed;
                continue;
            }

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

            progressedTranscript = true;
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
        if (processedCryptoFrame && !progressedTranscript && !replayedDuplicateInitialCrypto)
        {
            stateChanged |= TryReplayOutstandingCryptoAfterDuplicateInitialIngress(
                encryptionLevel,
                nowTicks,
                ref effects);
        }

        return stateChanged || processedCryptoFrame;
    }

    private bool IsDuplicateServerInitialCryptoFrame(
        QuicTlsEncryptionLevel encryptionLevel,
        QuicCryptoFrame cryptoFrame)
    {
        if (encryptionLevel != QuicTlsEncryptionLevel.Initial
            || tlsState.Role != QuicTlsRole.Server
            || phase != QuicConnectionPhase.Establishing
            || cryptoFrame.CryptoData.IsEmpty
            || cryptoFrame.Offset > QuicVariableLengthInteger.MaxValue - (ulong)cryptoFrame.CryptoData.Length)
        {
            return false;
        }

        ulong frameEndOffset = cryptoFrame.Offset + (ulong)cryptoFrame.CryptoData.Length;
        return frameEndOffset <= tlsState.InitialIngressCryptoBuffer.NextReadOffset;
    }

    private bool TryReplayOutstandingCryptoAfterDuplicateInitialIngress(
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (encryptionLevel != QuicTlsEncryptionLevel.Initial
            || tlsState.Role != QuicTlsRole.Server
            || phase != QuicConnectionPhase.Establishing
            || activePath is null)
        {
            return false;
        }

        if (tlsState.HandshakeKeysAvailable)
        {
            if (tlsState.InitialEgressCryptoBuffer.BufferedBytes > 0
                || tlsState.HandshakeEgressCryptoBuffer.BufferedBytes > 0)
            {
                return false;
            }

            return TrySendRecoveryProbeSequence(
                QuicPacketNumberSpace.Initial,
                QuicPacketNumberSpace.Handshake,
                QuicPacketNumberSpace.ApplicationData,
                nowTicks,
                ref effects);
        }

        if (tlsState.InitialEgressCryptoBuffer.BufferedBytes > 0)
        {
            return false;
        }

        return TryPromoteOutstandingProbePacket(QuicPacketNumberSpace.Initial)
            && TryFlushPendingRetransmissions(
                QuicPacketNumberSpace.Initial,
                nowTicks,
                probePacket: true,
                ref effects);
    }

    private bool TryHandleApplicationPacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if ((phase != QuicConnectionPhase.Active && phase != QuicConnectionPhase.Establishing)
            || activePath is null
            || !tlsState.OneRttKeysAvailable
            || !tlsState.OneRttOpenPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        bool stateChanged = false;
        bool openedWithCurrentOpenMaterial = false;
        bool openedWithRetainedOldOpenMaterial = false;
        if (handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacket(
            packetReceivedEvent.Datagram.Span,
            tlsState.OneRttOpenPacketProtectionMaterial.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase))
        {
            openedWithCurrentOpenMaterial = true;
        }
        else
        {
            bool openedWithRetainedOldKeys = tlsState.KeyUpdateInstalled
                && tlsState.CurrentOneRttKeyPhase == 1
                && tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue
                && handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacket(
                    packetReceivedEvent.Datagram.Span,
                    tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.Value,
                    out openedPacket,
                    out payloadOffset,
                    out payloadLength,
                    out bool oldKeyPhase)
                && !oldKeyPhase;

            if (openedWithRetainedOldKeys)
            {
                keyPhase = false;
                openedWithRetainedOldOpenMaterial = true;
            }
            else
            {
                // The first observed phase-1 packet may already require successor keys.
                if (!tlsBridgeDriver.TryEnsureNextOneRttOpenPacketProtectionMaterial(
                        out QuicTlsPacketProtectionMaterial successorOpenMaterial,
                        out bool retainedNextOpenMaterial))
                {
                    return false;
                }

                stateChanged |= retainedNextOpenMaterial;
                if (!tlsBridgeDriver.TryDeriveOneRttSuccessorPacketProtectionMaterial(
                        out QuicTlsPacketProtectionMaterial derivedSuccessorOpenMaterial,
                        out QuicTlsPacketProtectionMaterial successorProtectMaterial)
                    || !derivedSuccessorOpenMaterial.Matches(successorOpenMaterial)
                    || !handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacket(
                        packetReceivedEvent.Datagram.Span,
                        successorOpenMaterial,
                        out openedPacket,
                        out payloadOffset,
                        out payloadLength,
                        out bool successorKeyPhase)
                    || !successorKeyPhase
                    || !tlsState.TryInstallOneRttKeyUpdate(successorOpenMaterial, successorProtectMaterial)
                    || !tlsBridgeDriver.TryDiscardOneRttApplicationTrafficSecrets())
                {
                    return stateChanged;
                }

                keyPhase = true;
                stateChanged = true;
            }
        }

        if (openedWithCurrentOpenMaterial
            && keyPhase != ((tlsState.CurrentOneRttKeyPhase & 1U) == 1U))
        {
            return false;
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

        if (!TryExpandOpenedApplicationPacketNumber(openedPacket, payloadOffset, out ulong packetNumber))
        {
            if (ApplicationReceiveDebugEnabled)
            {
                Console.Error.WriteLine(
                    $"app-rx packet-number-failed role={tlsState.Role} payloadOffset={payloadOffset} datagram={packetReceivedEvent.Datagram.Length}.");
            }

            return false;
        }

        if (openedWithRetainedOldOpenMaterial
            && hasObservedCurrentOneRttKeyPhasePacketNumber
            && packetNumber >= lowestObservedCurrentOneRttKeyPhasePacketNumber)
        {
            return HandleFatalTlsSignal(
                packetReceivedEvent.ObservedAtTicks,
                QuicTransportErrorCode.KeyUpdateError,
                "The peer sent an old-key packet that violated packet-number ordering.",
                ref effects);
        }

        if (!openedWithRetainedOldOpenMaterial
            && keyPhase
            && tlsState.KeyUpdateInstalled
            && tlsState.CurrentOneRttKeyPhase == 1
            && TryArmRetainedOldOneRttKeyDiscard(nowTicks, ref effects))
        {
            stateChanged = true;
        }

        bool packetNumberAdvancesTheHighestObservedValue = !hasObservedApplicationPacketNumber
            || packetNumber > largestObservedApplicationPacketNumber;
        bool processedCryptoFrame = false;
        bool processedStreamFrame = false;
        bool processedMaxStreamsFrame = false;
        bool packetAckEliciting = false;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseAckFrame(remaining, out QuicAckFrame ackFrame, out int ackBytesConsumed))
            {
                if (ackBytesConsumed <= 0)
                {
                    return false;
                }

                stateChanged |= HandleApplicationAckFrame(
                    ackFrame,
                    nowTicks,
                    openedWithRetainedOldOpenMaterial,
                    ref effects);
                offset += ackBytesConsumed;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseMaxDataFrame(remaining, out QuicMaxDataFrame maxDataFrame, out int maxDataBytesConsumed))
            {
                if (maxDataBytesConsumed <= 0)
                {
                    return false;
                }

                if (streamRegistry.Bookkeeping.TryApplyMaxDataFrame(maxDataFrame))
                {
                    stateChanged = true;
                }

                offset += maxDataBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseMaxStreamDataFrame(remaining, out QuicMaxStreamDataFrame maxStreamDataFrame, out int maxStreamDataBytesConsumed))
            {
                if (maxStreamDataBytesConsumed <= 0)
                {
                    return false;
                }

                if (streamRegistry.Bookkeeping.TryApplyMaxStreamDataFrame(maxStreamDataFrame, out QuicTransportErrorCode maxStreamDataErrorCode))
                {
                    stateChanged = true;
                }
                else if (maxStreamDataErrorCode != default)
                {
                    return false;
                }

                offset += maxStreamDataBytesConsumed;
                packetAckEliciting = true;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseStreamDataBlockedFrame(
                remaining,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out int streamDataBlockedBytesConsumed))
            {
                if (streamDataBlockedBytesConsumed <= 0)
                {
                    return false;
                }

                if (!streamRegistry.Bookkeeping.TryReceiveStreamDataBlockedFrame(
                    streamDataBlockedFrame,
                    out QuicTransportErrorCode streamDataBlockedErrorCode))
                {
                    _ = streamDataBlockedErrorCode;
                    return false;
                }

                offset += streamDataBlockedBytesConsumed;
                packetAckEliciting = true;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseNewTokenFrame(remaining, out QuicNewTokenFrame _, out int newTokenBytesConsumed))
            {
                if (newTokenBytesConsumed <= 0)
                {
                    return false;
                }

                offset += newTokenBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseHandshakeDoneFrame(remaining, out QuicHandshakeDoneFrame _, out int handshakeDoneBytesConsumed))
            {
                if (handshakeDoneBytesConsumed <= 0)
                {
                    return false;
                }

                stateChanged |= TryHandleHandshakeDoneFrameReceived(nowTicks, ref effects);
                offset += handshakeDoneBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseConnectionCloseFrame(remaining, out QuicConnectionCloseFrame connectionCloseFrame, out int connectionCloseBytesConsumed))
            {
                if (connectionCloseBytesConsumed <= 0)
                {
                    return false;
                }

                QuicConnectionCloseMetadata closeMetadata = CreateCloseMetadata(connectionCloseFrame);
                stateChanged |= HandleConnectionCloseFrameReceived(
                    new QuicConnectionConnectionCloseFrameReceivedEvent(
                        nowTicks,
                        closeMetadata),
                    nowTicks,
                    ref effects);
                return stateChanged;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseRetireConnectionIdFrame(remaining, out QuicRetireConnectionIdFrame retireConnectionIdFrame, out int retireConnectionIdBytesConsumed))
            {
                if (retireConnectionIdBytesConsumed <= 0)
                {
                    return false;
                }

                if (!TryHandleRetireConnectionIdFrame(retireConnectionIdFrame, nowTicks, ref effects))
                {
                    return false;
                }

                stateChanged = true;
                offset += retireConnectionIdBytesConsumed;
                packetAckEliciting = true;
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
                packetAckEliciting = true;
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
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParsePathResponseFrame(remaining, out QuicPathResponseFrame pathResponseFrame, out int pathResponseBytesConsumed))
            {
                if (pathResponseBytesConsumed <= 0)
                {
                    return false;
                }

                if (!TryGetCandidatePath(packetReceivedEvent.PathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
                    || candidatePath.Validation.IsAbandoned
                    || candidatePath.Validation.IsValidated)
                {
                    offset += pathResponseBytesConsumed;
                    continue;
                }

                if (!candidatePath.Validation.ChallengePayload.Span.SequenceEqual(pathResponseFrame.Data))
                {
                    return HandleFatalTlsSignal(
                        nowTicks,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a PATH_RESPONSE frame that did not match the outstanding challenge.",
                        ref effects);
                }

                if (HandlePathValidationSucceeded(
                    new QuicConnectionPathValidationSucceededEvent(nowTicks, packetReceivedEvent.PathIdentity),
                    nowTicks,
                    ref effects))
                {
                    stateChanged = true;
                }

                offset += pathResponseBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
            {
                if (ApplicationReceiveDebugEnabled)
                {
                    Console.Error.WriteLine(
                        $"app-rx stream-parse-failed role={tlsState.Role} packet={packetNumber} remaining={remaining.Length}.");
                }

                return false;
            }

            if (streamFrame.ConsumedLength <= 0)
            {
                return false;
            }

            processedStreamFrame = true;
            if (ApplicationReceiveDebugEnabled)
            {
                Console.Error.WriteLine(
                    $"app-rx stream role={tlsState.Role} packet={packetNumber} stream={streamFrame.StreamId.Value} offset={streamFrame.Offset} length={streamFrame.StreamDataLength} fin={streamFrame.IsFin}.");
            }
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
            packetAckEliciting = true;
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

        if (packetNumberAdvancesTheHighestObservedValue
            && activePath is not null
            && !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, packetReceivedEvent.PathIdentity)
            && TryGetCandidatePath(packetReceivedEvent.PathIdentity, out QuicConnectionCandidatePathRecord receivePathCandidate)
            && receivePathCandidate.Validation.IsValidated
            && !receivePathCandidate.Validation.IsAbandoned
            && TryPromoteValidatedCandidatePath(packetReceivedEvent.PathIdentity, nowTicks, ref effects))
        {
            stateChanged = true;
        }

        sendRuntime.FlowController.RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            packetAckEliciting,
            GetElapsedMicros(nowTicks));

        largestObservedApplicationPacketNumber = hasObservedApplicationPacketNumber
            ? Math.Max(largestObservedApplicationPacketNumber, packetNumber)
            : packetNumber;
        hasObservedApplicationPacketNumber = true;
        if (!openedWithRetainedOldOpenMaterial
            && keyPhase
            && tlsState.KeyUpdateInstalled
            && tlsState.CurrentOneRttKeyPhase == 1)
        {
            lowestObservedCurrentOneRttKeyPhasePacketNumber = hasObservedCurrentOneRttKeyPhasePacketNumber
                ? Math.Min(lowestObservedCurrentOneRttKeyPhasePacketNumber, packetNumber)
                : packetNumber;
            hasObservedCurrentOneRttKeyPhasePacketNumber = true;
        }

        if (TrySendPendingApplicationAck(nowTicks, ref effects))
        {
            stateChanged = true;
        }

        return processedStreamFrame || processedCryptoFrame || stateChanged;
    }

    private bool TryExpandOpenedApplicationPacketNumber(byte[] openedPacket, int payloadOffset, out ulong packetNumber)
    {
        packetNumber = default;

        if (openedPacket.Length == 0
            || payloadOffset <= 0
            || payloadOffset > openedPacket.Length)
        {
            return false;
        }

        int packetNumberLength = (openedPacket[0] & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        int packetNumberOffset = payloadOffset - packetNumberLength;
        if (packetNumberLength < 1
            || packetNumberLength > sizeof(uint)
            || packetNumberOffset < 1
            || packetNumberOffset + packetNumberLength > openedPacket.Length)
        {
            return false;
        }

        ulong truncatedPacketNumber = 0;
        for (int index = packetNumberOffset; index < payloadOffset; index++)
        {
            truncatedPacketNumber = (truncatedPacketNumber << BitsPerByte) | openedPacket[index];
        }

        ulong expectedPacketNumber = hasObservedApplicationPacketNumber
            ? largestObservedApplicationPacketNumber + 1
            : 0;
        packetNumber = ExpandTruncatedPacketNumber(truncatedPacketNumber, packetNumberLength, expectedPacketNumber);
        return true;
    }

    private static ulong ExpandTruncatedPacketNumber(
        ulong truncatedPacketNumber,
        int packetNumberLength,
        ulong expectedPacketNumber)
    {
        int packetNumberBits = checked(packetNumberLength * BitsPerByte);
        ulong packetNumberWindow = 1UL << packetNumberBits;
        ulong packetNumberHalfWindow = packetNumberWindow / 2;
        ulong packetNumberMask = packetNumberWindow - 1;
        ulong candidatePacketNumber = (expectedPacketNumber & ~packetNumberMask) | truncatedPacketNumber;

        if (candidatePacketNumber + packetNumberHalfWindow <= expectedPacketNumber
            && candidatePacketNumber <= ulong.MaxValue - packetNumberWindow)
        {
            candidatePacketNumber += packetNumberWindow;
        }
        else if (candidatePacketNumber > expectedPacketNumber + packetNumberHalfWindow
            && candidatePacketNumber >= packetNumberWindow)
        {
            candidatePacketNumber -= packetNumberWindow;
        }

        return candidatePacketNumber;
    }

    private static QuicConnectionCloseMetadata CreateCloseMetadata(QuicConnectionCloseFrame frame)
    {
        string? reasonPhrase = frame.ReasonPhrase.IsEmpty
            ? null
            : System.Text.Encoding.UTF8.GetString(frame.ReasonPhrase);

        return frame.IsApplicationError
            ? new QuicConnectionCloseMetadata(
                TransportErrorCode: null,
                ApplicationErrorCode: frame.ErrorCode,
                TriggeringFrameType: null,
                ReasonPhrase: reasonPhrase)
            : new QuicConnectionCloseMetadata(
                TransportErrorCode: (QuicTransportErrorCode)frame.ErrorCode,
                ApplicationErrorCode: null,
                TriggeringFrameType: frame.TriggeringFrameType,
                ReasonPhrase: reasonPhrase);
    }

    private bool HandleApplicationAckFrame(
        QuicAckFrame ackFrame,
        long nowTicks,
        bool receivedInRetainedOldOneRttPacket,
        ref List<QuicConnectionEffect>? effects)
    {
        return HandleAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            nowTicks,
            receivedInRetainedOldOneRttPacket,
            ref effects);
    }

    private bool HandleAckFrame(
        QuicPacketNumberSpace packetNumberSpace,
        QuicAckFrame ackFrame,
        long nowTicks,
        bool receivedInRetainedOldOneRttPacket,
        ref List<QuicConnectionEffect>? effects)
    {
        ArgumentNullException.ThrowIfNull(ackFrame);

        ulong ackReceivedAtMicros = GetElapsedMicros(nowTicks);
        HashSet<ulong> acknowledgedPacketNumbers = [];
        List<ulong> newlyAcknowledgedAckElicitingPacketNumbers = [];
        bool acknowledgedCurrentOneRttKeyPhasePacket = false;

        foreach (ulong packetNumber in EnumerateAcknowledgedPacketNumbers(ackFrame))
        {
            if (!acknowledgedPacketNumbers.Add(packetNumber))
            {
                continue;
            }

            if (sendRuntime.SentPackets.TryGetValue(
                    new QuicConnectionSentPacketKey(packetNumberSpace, packetNumber),
                    out QuicConnectionSentPacket sentPacket))
            {
                if (receivedInRetainedOldOneRttPacket
                    && packetNumberSpace == QuicPacketNumberSpace.ApplicationData
                    && sentPacket.OneRttKeyPhase == 1)
                {
                    return HandleFatalTlsSignal(
                        nowTicks,
                        QuicTransportErrorCode.KeyUpdateError,
                        "The peer acknowledged a newer-key packet in an old-key packet.",
                        ref effects);
                }

                if (packetNumberSpace == QuicPacketNumberSpace.ApplicationData
                    && tlsState.KeyUpdateInstalled
                    && sentPacket.OneRttKeyPhase == tlsState.CurrentOneRttKeyPhase)
                {
                    acknowledgedCurrentOneRttKeyPhasePacket = true;
                }

                if (sentPacket.AckEliciting)
                {
                    newlyAcknowledgedAckElicitingPacketNumbers.Add(packetNumber);
                }
            }
        }

        bool stateChanged = sendRuntime.FlowController.TryProcessAckFrame(
            packetNumberSpace,
            ackFrame,
            ackReceivedAtMicros,
            pathValidated: HasValidatedPath);

        foreach (ulong packetNumber in acknowledgedPacketNumbers)
        {
            stateChanged |= sendRuntime.TryAcknowledgePacket(
                packetNumberSpace,
                packetNumber,
                handshakeConfirmed: HandshakeConfirmed);
        }

        stateChanged |= recoveryController.RecordAcknowledgment(
            packetNumberSpace,
            ackFrame.LargestAcknowledged,
            ackReceivedAtMicros,
            newlyAcknowledgedAckElicitingPacketNumbers.ToArray(),
            ackDelayMicros: ackFrame.AckDelay,
            handshakeConfirmed: HandshakeConfirmed,
            peerMaxAckDelayMicros: tlsState.PeerTransportParameters?.MaxAckDelay ?? 0);

        stateChanged |= TryRegisterDetectedLosses(nowTicks);
        if (acknowledgedCurrentOneRttKeyPhasePacket && TryRecordConfirmedCurrentOneRttKeyPhase(nowTicks))
        {
            stateChanged = true;
        }

        if (TryFlushPendingRetransmissions(
            packetNumberSpace,
            nowTicks,
            probePacket: false,
            ref effects))
        {
            stateChanged = true;
        }

        return stateChanged;
    }

    private bool TryRecordConfirmedCurrentOneRttKeyPhase(long nowTicks)
    {
        if (!tlsState.KeyUpdateInstalled || tlsState.CurrentOneRttKeyPhase == 0)
        {
            return false;
        }

        RefreshCurrentProbeTimeoutMicros(nowTicks);
        return tlsState.TryRecordCurrentOneRttKeyPhaseAcknowledgment(
            GetElapsedMicros(nowTicks),
            currentProbeTimeoutMicros);
    }

    private bool TrySendPendingApplicationAck(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (activePath is null || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        ulong nowMicros = GetElapsedMicros(nowTicks);
        if (!sendRuntime.FlowController.CanSendAckOnlyPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros,
            maxAckDelayMicros: 0)
            || !sendRuntime.FlowController.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                out QuicAckFrame ackFrame)
            || !TryBuildOutboundAckPayload(ackFrame, out byte[] ackPayload))
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayload(
            ackPayload,
            "The connection runtime could not protect the ACK packet.",
            "The connection cannot send the ACK packet.",
            probePacket: false,
            ackOnlyPacket: true,
            streamIds: null,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out byte[] protectedPacket,
            out _))
        {
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        sendRuntime.FlowController.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros,
            ackOnlyPacket: true);

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TryBuildOutboundAckPayload(QuicAckFrame ackFrame, out byte[] payload)
    {
        payload = [];

        byte[] buffer = new byte[Math.Max(ApplicationMinimumProtectedPayloadLength, 512)];
        if (!QuicFrameCodec.TryFormatAckFrame(ackFrame, buffer, out int frameBytesWritten))
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

    private static IEnumerable<ulong> EnumerateAcknowledgedPacketNumbers(QuicAckFrame ackFrame)
    {
        if (ackFrame.LargestAcknowledged < ackFrame.FirstAckRange)
        {
            yield break;
        }

        ulong largestAcknowledged = ackFrame.LargestAcknowledged;
        ulong smallestAcknowledged = largestAcknowledged - ackFrame.FirstAckRange;
        for (ulong packetNumber = smallestAcknowledged; ; packetNumber++)
        {
            yield return packetNumber;
            if (packetNumber == largestAcknowledged)
            {
                break;
            }
        }

        foreach (QuicAckRange range in ackFrame.AdditionalRanges)
        {
            for (ulong packetNumber = range.SmallestAcknowledged; ; packetNumber++)
            {
                yield return packetNumber;
                if (packetNumber == range.LargestAcknowledged)
                {
                    break;
                }
            }
        }
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

    private bool TryHandleRetireConnectionIdFrame(
        QuicRetireConnectionIdFrame retireConnectionIdFrame,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (retireConnectionIdFrame.SequenceNumber > highestConnectionIdIssuedToPeer)
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer retired an unknown connection ID.",
                ref effects);
        }

        if (peerConnectionIdState.CurrentDestinationConnectionIdSequence.HasValue
            && retireConnectionIdFrame.SequenceNumber == peerConnectionIdState.CurrentDestinationConnectionIdSequence.Value)
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer retired the packet destination connection ID.",
                ref effects);
        }

        return true;
    }

    private bool TryFlushInitialPackets(
        ref List<QuicConnectionEffect>? effects,
        bool probePacket = false,
        int maximumDatagrams = int.MaxValue)
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
                probePacket: false,
                maximumDatagrams: int.MaxValue,
                ref effects);

            if (replayed)
            {
                retryBootstrapPendingReplay = false;
            }

            return replayed;
        }

        if (tlsState.InitialEgressCryptoBuffer.BufferedBytes <= 0)
        {
            return probePacket
                && tlsState.Role == QuicTlsRole.Client
                && initialBootstrapClientHelloBytes is not null
                && initialBootstrapClientHelloBytes.Length > 0
                && (
                    retrySourceConnectionId is not null
                    && retryToken is not null
                    ? TryFlushRetriedInitialPackets(
                        pathIdentity,
                        initialBootstrapClientHelloBytes,
                        retrySourceConnectionId,
                        retryToken,
                        initialPacketProtection,
                        probePacket,
                        maximumDatagrams,
                        ref effects)
                    : TryReplayBootstrapInitialPackets(
                        pathIdentity,
                        initialBootstrapClientHelloBytes,
                        initialPacketProtection,
                        probePacket,
                        maximumDatagrams,
                        ref effects));
        }

        bool stateChanged = false;
        int datagramsSent = 0;
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

                TrackInitialPacket(packetNumber, protectedPacket, probePacket);
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

                TrackInitialPacket(packetNumber, protectedPacket, probePacket);
            }

            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
            stateChanged = true;

            datagramsSent++;
            if (datagramsSent >= maximumDatagrams)
            {
                break;
            }
        }

        return stateChanged;
    }

    private bool TryReplayBootstrapInitialPackets(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> initialClientHelloBytes,
        QuicInitialPacketProtection protection,
        bool probePacket,
        int maximumDatagrams,
        ref List<QuicConnectionEffect>? effects)
    {
        if (initialClientHelloBytes.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        int datagramsSent = 0;
        int replayOffset = 0;
        Span<byte> cryptoBuffer = stackalloc byte[HandshakeEgressChunkBytes];

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
                    protection,
                    out ulong packetNumber,
                    out byte[] protectedPacket))
            {
                break;
            }

            TrackInitialPacket(packetNumber, protectedPacket, probePacket);
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));

            replayOffset += requestedBytes;
            datagramsSent++;
            stateChanged = true;

            if (datagramsSent >= maximumDatagrams)
            {
                break;
            }
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
        TrackApplicationPacket(
            packetNumber,
            protectedPacket,
            retransmittable: false,
            probePacket: true,
            packetProtectionLevel: QuicTlsEncryptionLevel.ZeroRtt);
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
        bool probePacket,
        int maximumDatagrams,
        ref List<QuicConnectionEffect>? effects)
    {
        if (initialClientHelloBytes.IsEmpty)
        {
            return false;
        }

        bool stateChanged = false;
        int datagramsSent = 0;
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

            TrackInitialPacket(packetNumber, protectedPacket, probePacket);
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
            replayOffset += requestedBytes;
            datagramsSent++;
            stateChanged = true;

            if (datagramsSent >= maximumDatagrams)
            {
                break;
            }
        }

        return stateChanged;
    }

    private bool TryFlushHandshakePackets(
        ref List<QuicConnectionEffect>? effects,
        bool probePacket = false,
        int maximumDatagrams = int.MaxValue)
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
        int datagramsSent = 0;
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

            TrackHandshakePacket(packetNumber, protectedPacket, probePacket);
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketSent(currentPath.Identity, protectedPacket));
            }
            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                protectedPacket));
            stateChanged = true;

            datagramsSent++;
            if (datagramsSent >= maximumDatagrams)
            {
                break;
            }
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

    private bool TryHandleHandshakeDoneFrameReceived(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (tlsState.Role == QuicTlsRole.Server)
        {
            QuicConnectionCloseMetadata closeMetadata = new(
                TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
                ApplicationErrorCode: null,
                TriggeringFrameType: 0x1E,
                ReasonPhrase: "The server received a HANDSHAKE_DONE frame.");

            return HandleLocalCloseRequested(
                new QuicConnectionLocalCloseRequestedEvent(nowTicks, closeMetadata),
                nowTicks,
                ref effects);
        }

        if (handshakeConfirmed)
        {
            return false;
        }

        handshakeConfirmed = true;
        bool stateChanged = true;
        stateChanged |= TryPublishTlsKeyDiscard(
            QuicTlsEncryptionLevel.Handshake,
            nowTicks,
            ref effects);
        return stateChanged;
    }

    private bool TryFlushNewTokenEmissions(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (phase != QuicConnectionPhase.Active
            || tlsState.Role != QuicTlsRole.Server
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue
            || newTokenEmissionsByRemoteAddress.Count == 0)
        {
            return false;
        }

        bool stateChanged = false;
        foreach (KeyValuePair<string, QuicConnectionNewTokenEmissionRecord> entry in newTokenEmissionsByRemoteAddress.ToArray())
        {
            if (entry.Value.IsEmitted)
            {
                continue;
            }

            stateChanged |= TryFlushNewTokenEmission(entry.Value, nowTicks, ref effects);
        }

        return stateChanged;
    }

    private bool TryQueueNewTokenEmission(
        QuicConnectionPathIdentity pathIdentity,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (tlsState.Role != QuicTlsRole.Server)
        {
            return false;
        }

        string remoteAddress = pathIdentity.RemoteAddress;
        if (newTokenEmissionsByRemoteAddress.TryGetValue(remoteAddress, out QuicConnectionNewTokenEmissionRecord? emissionRecord))
        {
            if (emissionRecord.IsEmitted)
            {
                return false;
            }

            emissionRecord.PathIdentity = pathIdentity;
        }
        else
        {
            emissionRecord = new QuicConnectionNewTokenEmissionRecord(pathIdentity, CreateAddressValidationToken());
            newTokenEmissionsByRemoteAddress.Add(remoteAddress, emissionRecord);
        }

        return TryFlushNewTokenEmission(emissionRecord, nowTicks, ref effects);
    }

    private bool TryFlushNewTokenEmission(
        QuicConnectionNewTokenEmissionRecord emissionRecord,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (emissionRecord.IsEmitted)
        {
            return false;
        }

        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }
        if (!TryBuildOutboundNewTokenPayload(emissionRecord.Token, out byte[] payload))
        {
            return false;
        }

        QuicConnectionPathIdentity sendPathIdentity;
        if (TryGetCandidatePath(emissionRecord.PathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
            && candidatePath.Validation.IsValidated
            && !candidatePath.Validation.IsAbandoned)
        {
            sendPathIdentity = candidatePath.Identity;
        }
        else if (activePath.HasValue)
        {
            sendPathIdentity = activePath.Value.Identity;
        }
        else
        {
            return false;
        }

        if (!TryProtectAndAccountApplicationPayloadOnPath(
            sendPathIdentity,
            payload,
            "The connection runtime could not protect the NEW_TOKEN packet.",
            "The connection cannot send the NEW_TOKEN packet.",
            out QuicConnectionPathIdentity actualPathIdentity,
            out byte[] protectedPacket,
            out Exception? exception))
        {
            _ = exception;
            return false;
        }

        emissionRecord.IsEmitted = true;
        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(actualPathIdentity, protectedPacket));
        _ = nowTicks;
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

        bool stateChanged = streamRegistry.Bookkeeping.TryApplyPeerTransportParameterSendLimits(
            localBidirectionalLimit: peerTransportParameters.InitialMaxStreamDataBidiRemote ?? 0,
            peerBidirectionalLimit: peerTransportParameters.InitialMaxStreamDataBidiLocal ?? 0,
            localUnidirectionalLimit: peerTransportParameters.InitialMaxStreamDataUni ?? 0);

        stateChanged |= TryCommitPeerStreamLimits(
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

        bool stateChanged = false;
        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                stateChanged |= sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial);
                stateChanged |= recoveryController.TryDiscardPacketNumberSpace(
                    QuicPacketNumberSpace.Initial,
                    resetProbeTimeoutBackoff: true);
                break;
            case QuicTlsEncryptionLevel.Handshake:
                stateChanged |= sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake);
                stateChanged |= recoveryController.TryDiscardPacketNumberSpace(
                    QuicPacketNumberSpace.Handshake,
                    resetProbeTimeoutBackoff: true);
                break;
            case QuicTlsEncryptionLevel.ZeroRtt:
                stateChanged |= sendRuntime.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt);
                stateChanged |= recoveryController.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt);
                break;
            case QuicTlsEncryptionLevel.OneRtt:
                break;
        }

        return stateChanged;
    }

    private bool TryPublishTlsKeyDiscard(
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        IReadOnlyList<QuicTlsStateUpdate> updates = tlsBridgeDriver.PublishKeyDiscard(encryptionLevel);
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
}
