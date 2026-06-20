// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// TLS/bootstrap handling, packet ingress, and transport-parameter commits.
internal sealed partial class QuicConnectionRuntime
{
    private const int BitsPerByte = 8;
    private const ulong MaximumStreamLimit = 1UL << 60;
    private static readonly bool ApplicationReceiveDebugEnabled =
        string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DEBUG_APP_RX"),
            "1",
            StringComparison.Ordinal);
    private static readonly bool ApplicationReceiveRejectDiagnosticsEnabled =
        ApplicationReceiveDebugEnabled
        || string.Equals(
            Environment.GetEnvironmentVariable("INCURSA_QUIC_DIAG_APP_RX_REJECTS"),
            "1",
            StringComparison.Ordinal);

    private bool CanReceiveGreasedQuicBitPackets =>
        tlsState.LocalTransportParameters?.GreaseQuicBit == true;

    private bool PeerSupportsGreasedQuicBit =>
        tlsState.PeerTransportParameters?.GreaseQuicBit == true;

    private bool HandlePeerHandshakeTranscriptCompleted(
        QuicConnectionPeerHandshakeTranscriptCompletedEvent peerHandshakeTranscriptCompletedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        _ = peerHandshakeTranscriptCompletedEvent;

        bool stateChanged = tlsState.TryMarkPeerHandshakeTranscriptCompleted();

        if (!peerHandshakeTranscriptCompleted)
        {
            peerHandshakeTranscriptCompleted = true;
            stateChanged = true;
            ClearBufferedEstablishmentHandshakePackets();
            EmitDiagnostic(ref effects, QuicDiagnostics.PeerHandshakeTranscriptCompleted());

            if (phase == QuicConnectionPhase.Establishing)
            {
                phase = QuicConnectionPhase.Active;
            }

            // CONTEXT: The supported client floor still treats transcript completion as the current
            // bootstrap-path validation proof point so the active path does not remain stuck in a
            // bootstrap-only state once the peer handshake flight is proven. Recovery-level handshake
            // confirmation remains a separate client-side signal.
            // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Protocol.cs#HandleHandshakeBootstrapRequested
            // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Paths.cs#TryMarkActivePathValidated
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
            stateChanged |= TryFlushOneRttCryptoPackets(ref effects);
            stateChanged |= TryEnsureInitialPeerUsableConnectionId(ref effects);
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
                stateChanged |= TryPublishTlsKeyDiscard(
                    QuicTlsEncryptionLevel.ZeroRtt,
                    nowTicks,
                    ref effects);
            }
        }

        AppendLifecycleTimerEffects(ref effects);
        return stateChanged;
    }

    private bool TryEnsureInitialPeerUsableConnectionId(ref QuicConnectionEffectAccumulator effects)
    {
        if (!enableInitialPeerUsableConnectionId
            || issuedConnectionIdState.TotalIssuedConnectionIdCount != 0)
        {
            return false;
        }

        return TryReplenishIssuedConnectionId(ref effects);
    }

    private bool HandleHandshakeBootstrapRequested(
        QuicConnectionHandshakeBootstrapRequestedEvent handshakeBootstrapRequestedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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

        if (tlsState.Role == QuicTlsRole.Client
            && !handshakeBootstrapRequestedEvent.InitialAddressValidationToken.IsEmpty)
        {
            initialAddressValidationToken = handshakeBootstrapRequestedEvent.InitialAddressValidationToken.ToArray();
        }

        QuicTlsStateUpdateBatch updates = tlsBridgeDriver.StartHandshake(
            localTransportParameters,
            dormantDetachedResumptionTicketSnapshot,
            nowTicks);
        if (updates.Count == 0)
        {
            return false;
        }

        bool stateChanged = true;
        stateChanged |= ApplyTlsStateUpdates(
            updates,
            handshakeBootstrapRequestedEvent.ObservedAtTicks,
            nowTicks,
            ref effects);

        QuicTlsStateUpdateBatch replayedHandshakeUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(QuicTlsEncryptionLevel.Handshake);
        if (replayedHandshakeUpdates.Count > 0)
        {
            stateChanged = true;
            stateChanged |= ApplyTlsStateUpdates(
                replayedHandshakeUpdates,
                handshakeBootstrapRequestedEvent.ObservedAtTicks,
                nowTicks,
                ref effects);
        }

        return stateChanged;
    }

    private bool HandleRetryReceived(
        QuicConnectionRetryReceivedEvent retryReceivedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        _ = nowTicks;
        _ = effects;

        if (phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || retryBootstrapPendingReplay
            || retrySourceConnectionId is not null
            || observedPeerInitialSourceConnectionId is not null
            || retryReceivedEvent.RetrySourceConnectionId.IsEmpty
            || retryReceivedEvent.RetryToken.IsEmpty)
        {
            return false;
        }

        if (!TryConfigureRetryInitialPacketProtection(
            versionProfile.SelectedVersion,
            retryReceivedEvent.RetrySourceConnectionId.Span))
        {
            return false;
        }

        ResetRecoveryStateForRetry();
        retrySourceConnectionId = retryReceivedEvent.RetrySourceConnectionId.ToArray();
        retryToken = retryReceivedEvent.RetryToken.ToArray();
        initialAddressValidationToken = null;
        observedPeerInitialCryptoFrameData = null;
        ClearBufferedEstablishmentHandshakePackets();
        retryBootstrapPendingReplay = true;
        hasSuccessfullyProcessedAnotherPacket = true;

        bool stateChanged = true;
        stateChanged |= TrySetHandshakeDestinationConnectionId(retryReceivedEvent.RetrySourceConnectionId.Span);
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.RetryReceived(retryReceivedEvent.Datagram.Span));
        }

        stateChanged |= TryFlushInitialPackets(ref effects);
        AppendLifecycleTimerEffects(ref effects);
        return stateChanged;
    }

    private bool HandleVersionNegotiationReceived(
        QuicConnectionVersionNegotiationReceivedEvent versionNegotiationReceivedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.VersionNegotiationReceived(versionNegotiationReceivedEvent.Datagram.Span));
        }

        return DiscardConnection(
            versionNegotiationReceivedEvent.ObservedAtTicks,
            QuicConnectionCloseOrigin.VersionNegotiation,
            default,
            ref effects);
    }

    private bool HandleTlsStateUpdated(
        QuicConnectionTlsStateUpdatedEvent tlsStateUpdatedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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

            case QuicTlsUpdateKind.KeyLogSecretAvailable:
                if (tlsStateUpdatedEvent.Update.KeyLogSecret is { } keyLogSecret)
                {
                    tlsKeyLogSecretObserver?.Invoke(keyLogSecret);
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
                stateChanged |= TryFlushOneRttCryptoPackets(ref effects);
                stateChanged |= TryFlushNewTokenEmissions(nowTicks, ref effects);
                break;
        }

        stateChanged |= TryCaptureResumptionMasterSecret();
        if (stateChanged)
        {
            AppendLifecycleTimerEffects(ref effects);
        }

        return stateChanged;
    }

    private bool HandleCryptoFrameReceived(
        QuicConnectionCryptoFrameReceivedEvent cryptoFrameReceivedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
    {
        ReadOnlyMemory<byte> datagram = packetReceivedEvent.Datagram;
        if (!QuicPacketParser.TryGetPacketNumberSpace(
                datagram.Span,
                CanReceiveGreasedQuicBitPackets,
                out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Initial
            || !QuicPacketParsing.TryParseLongHeaderMemoryFields(
                datagram,
                out _,
                out uint packetVersion,
                out _,
                out ReadOnlyMemory<byte> sourceConnectionId,
                out _)
            || !TryGetIncomingInitialPacketProtection(packetVersion, out QuicInitialPacketProtection packetProtection))
        {
            return false;
        }

        if (ShouldDiscardClientLongHeaderPacketWithUnexpectedPeerSourceConnectionId(sourceConnectionId.Span))
        {
            return false;
        }

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketReceived(packetReceivedEvent.PathIdentity, datagram.Span));
        }

        if (!handshakeFlowCoordinator.TryOpenInitialPacketLease(
                datagram.Span,
                packetProtection,
                requireZeroTokenLength: tlsState.Role == QuicTlsRole.Client,
                allowClearedFixedBit: CanReceiveGreasedQuicBitPackets,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketOpenFailed(packetReceivedEvent.PathIdentity, datagram.Span));
            }

            return false;
        }

        using (openedPacket)
        {
            ReadOnlySpan<byte> payload = openedPacket.Span.Slice(payloadOffset, payloadLength);
            QuicWeaklyProtectedPacketPayloadValidationResult payloadValidation =
                QuicPacketFrameLegality.ValidateWeaklyProtectedHandshakePayload(payload, QuicTlsEncryptionLevel.Initial);
            if (payloadValidation == QuicWeaklyProtectedPacketPayloadValidationResult.Discard)
            {
                return false;
            }

            if (payloadValidation == QuicWeaklyProtectedPacketPayloadValidationResult.ConnectionError)
            {
                return HandleFatalTlsSignal(
                    nowTicks,
                    QuicTransportErrorCode.ProtocolViolation,
                    "The peer sent a frame in a weakly protected packet type that is not permitted.",
                    ref effects);
            }

            ReadOnlyMemory<byte>? acceptedPeerInitialSourceConnectionId = null;
            if (tlsState.Role == QuicTlsRole.Client
                && phase == QuicConnectionPhase.Establishing
                && !peerHandshakeTranscriptCompleted
                )
            {
                acceptedPeerInitialSourceConnectionId = sourceConnectionId;
                bool hasOffsetZeroInitialCrypto = QuicTlsClientHelloExtensions.TryExtractOffsetZeroInitialCryptoFrameData(
                    payload,
                    out ReadOnlySpan<byte> initialCryptoFrameData);

                if (observedPeerInitialSourceConnectionId is null)
                {
                    observedPeerInitialSourceConnectionId = sourceConnectionId;
                    if (retrySourceConnectionId is null)
                    {
                        _ = TrySetHandshakeDestinationConnectionId(sourceConnectionId.Span);
                    }

                    if (hasOffsetZeroInitialCrypto)
                    {
                        observedPeerInitialCryptoFrameData = initialCryptoFrameData.ToArray();
                    }
                }
                else if (hasOffsetZeroInitialCrypto)
                {
                    bool differentInitialSourceConnectionId =
                        !observedPeerInitialSourceConnectionId.Value.Span.SequenceEqual(sourceConnectionId.Span);

                    if (differentInitialSourceConnectionId
                        && observedPeerInitialCryptoFrameData is not null
                        && !HasMatchingInitialCryptoPrefix(
                            observedPeerInitialCryptoFrameData.Value.Span,
                            initialCryptoFrameData))
                    {
                        _ = TryResetClientPeerHandshakeAttempt(
                            sourceConnectionId.Span,
                            initialCryptoFrameData);
                    }
                    else if (observedPeerInitialCryptoFrameData is null
                        || (HasMatchingInitialCryptoPrefix(
                                observedPeerInitialCryptoFrameData.Value.Span,
                                initialCryptoFrameData)
                            && initialCryptoFrameData.Length > observedPeerInitialCryptoFrameData.Value.Length))
                    {
                        observedPeerInitialCryptoFrameData = initialCryptoFrameData.ToArray();
                    }
                }
            }

            bool processed = TryProcessHandshakePacketPayload(
                payload,
                QuicTlsEncryptionLevel.Initial,
                nowTicks,
                out bool packetAckEliciting,
                out bool packetProcessed,
                ref effects);
            if (packetProcessed)
            {
                if (!TryExpandOpenedPacketNumber(
                        openedPacket.Span,
                        payloadOffset,
                        QuicPacketNumberSpace.Initial,
                        out ulong packetNumber))
                {
                    return false;
                }

                RecordIncomingPacket(
                    QuicPacketNumberSpace.Initial,
                    packetNumber,
                    packetAckEliciting,
                    nowTicks,
                    packetReceivedEvent.EcnCounts);
                UpdateObservedPacketNumber(QuicPacketNumberSpace.Initial, packetNumber);
            }

            if (processed
                && acceptedPeerInitialSourceConnectionId is not null)
            {
                processed |= TryReplayBufferedEstablishmentHandshakePackets(
                    acceptedPeerInitialSourceConnectionId.Value.Span,
                    nowTicks,
                    ref effects);
            }

            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketProcessingResult(processed));
            }

            return processed;
        }
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

    private bool ShouldDiscardClientLongHeaderPacketWithUnexpectedPeerSourceConnectionId(ReadOnlySpan<byte> sourceConnectionId)
    {
        if (allowClientPeerInitialReplacementBeforeTranscript
            || tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || peerHandshakeTranscriptCompleted
            || observedPeerInitialSourceConnectionId is null)
        {
            return false;
        }

        return !observedPeerInitialSourceConnectionId.Value.Span.SequenceEqual(sourceConnectionId);
    }

    private bool TryHandleHandshakePacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
    {
        ReadOnlyMemory<byte> datagram = packetReceivedEvent.Datagram;
        if (!QuicPacketParser.TryGetPacketNumberSpace(
                datagram.Span,
                CanReceiveGreasedQuicBitPackets,
                out QuicPacketNumberSpace packetNumberSpace)
            || packetNumberSpace != QuicPacketNumberSpace.Handshake
            || !QuicPacketParsing.TryParseLongHeaderMemoryFields(
                datagram,
                out _,
                out uint packetVersion,
                out _,
                out ReadOnlyMemory<byte> sourceConnectionId,
                out _))
        {
            return false;
        }

        if (tlsState.Role == QuicTlsRole.Client
            && packetVersion != versionProfile.SelectedVersion
            && !TryAdoptNegotiatedVersion(packetVersion))
        {
            return false;
        }

        if (ShouldDiscardClientLongHeaderPacketWithUnexpectedPeerSourceConnectionId(sourceConnectionId.Span))
        {
            return false;
        }

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketReceived(packetReceivedEvent.PathIdentity, datagram.Span));
        }

        if (!tlsState.TryGetHandshakeOpenPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(
                    packetReceivedEvent.PathIdentity,
                    "missing-open-material",
                    datagram.Span));
            }

            if (allowDeferredBuffering)
            {
                _ = TryBufferEstablishmentHandshakePacketForDeferredRetry(packetReceivedEvent);
            }

            return false;
        }

        if (!handshakeFlowCoordinator.TryOpenHandshakePacketLease(
                datagram.Span,
                packetProtectionMaterial,
                allowClearedFixedBit: CanReceiveGreasedQuicBitPackets,
                out QuicBufferLease openedPacket,
                out int payloadOffset,
                out int payloadLength))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketOpenFailed(
                    packetReceivedEvent.PathIdentity,
                    "decrypt-or-layout-failed",
                    datagram.Span));
            }

            if (allowDeferredBuffering)
            {
                _ = TryBufferEstablishmentHandshakePacketForDeferredRetry(packetReceivedEvent);
            }

            return false;
        }

        try
        {
            ReadOnlySpan<byte> payload = openedPacket.Span.Slice(payloadOffset, payloadLength);
            QuicWeaklyProtectedPacketPayloadValidationResult payloadValidation =
                QuicPacketFrameLegality.ValidateWeaklyProtectedHandshakePayload(payload, QuicTlsEncryptionLevel.Handshake);
            if (payloadValidation == QuicWeaklyProtectedPacketPayloadValidationResult.Discard)
            {
                return false;
            }

            if (payloadValidation == QuicWeaklyProtectedPacketPayloadValidationResult.ConnectionError)
            {
                return HandleFatalTlsSignal(
                    nowTicks,
                    QuicTransportErrorCode.ProtocolViolation,
                    "The peer sent a frame in a weakly protected packet type that is not permitted.",
                    ref effects);
            }

            bool processed = TryProcessHandshakePacketPayload(
                payload,
                QuicTlsEncryptionLevel.Handshake,
                nowTicks,
                out bool packetAckEliciting,
                out bool packetProcessed,
                ref effects);
            if (packetProcessed)
            {
                if (!TryExpandOpenedPacketNumber(
                        openedPacket.Span,
                        payloadOffset,
                        QuicPacketNumberSpace.Handshake,
                        out ulong packetNumber))
                {
                    return false;
                }

                RecordIncomingPacket(
                    QuicPacketNumberSpace.Handshake,
                    packetNumber,
                    packetAckEliciting,
                    nowTicks,
                    packetReceivedEvent.EcnCounts);
                UpdateObservedPacketNumber(QuicPacketNumberSpace.Handshake, packetNumber);
            }

            if (processed)
            {
                processed |= TryPublishTlsKeyDiscard(
                    QuicTlsEncryptionLevel.Initial,
                    nowTicks,
                    ref effects);
            }

            return processed;
        }
        finally
        {
            openedPacket.Dispose();
        }
    }

    private bool TryBufferEstablishmentHandshakePacketForDeferredRetry(
        QuicConnectionPacketReceivedEvent packetReceivedEvent)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || tlsState.IsTerminal
            || peerHandshakeTranscriptCompleted
            || !QuicPacketParsing.TryParseLongHeaderMemoryFields(
                packetReceivedEvent.Datagram,
                out _,
                out _,
                out _,
                out ReadOnlyMemory<byte> sourceConnectionId,
                out _)
            || sourceConnectionId.IsEmpty
            || (observedPeerInitialSourceConnectionId is not null
                && !allowClientPeerInitialReplacementBeforeTranscript
                && !observedPeerInitialSourceConnectionId.Value.Span.SequenceEqual(sourceConnectionId.Span))
            || (observedPeerInitialSourceConnectionId is not null
                && observedPeerInitialSourceConnectionId.Value.Span.SequenceEqual(sourceConnectionId.Span)))
        {
            return false;
        }

        foreach (BufferedEstablishmentHandshakePacket bufferedPacket in bufferedEstablishmentHandshakePackets)
        {
            if (bufferedPacket.SourceConnectionId.Span.SequenceEqual(sourceConnectionId.Span)
                && bufferedPacket.Datagram.Span.SequenceEqual(packetReceivedEvent.Datagram.Span))
            {
                return true;
            }
        }

        if (bufferedEstablishmentHandshakePackets.Count >= MaximumBufferedEstablishmentHandshakePackets)
        {
            RemoveBufferedEstablishmentHandshakePacketAt(0);
        }

        byte[] sourceConnectionIdBuffer = QuicBufferPool.RentBytes(sourceConnectionId.Length);
        sourceConnectionId.CopyTo(sourceConnectionIdBuffer);
        byte[] datagramBuffer = QuicBufferPool.RentBytes(packetReceivedEvent.Datagram.Length);
        packetReceivedEvent.Datagram.CopyTo(datagramBuffer);

        bufferedEstablishmentHandshakePackets.Add(new BufferedEstablishmentHandshakePacket(
            packetReceivedEvent.PathIdentity,
            sourceConnectionIdBuffer,
            sourceConnectionId.Length,
            datagramBuffer,
            packetReceivedEvent.Datagram.Length,
            packetReceivedEvent.EcnCounts));

        return true;
    }

    private bool TryReplayBufferedEstablishmentHandshakePackets(
        ReadOnlySpan<byte> acceptedPeerInitialSourceConnectionId,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
            if (!bufferedPacket.SourceConnectionId.Span.SequenceEqual(acceptedPeerInitialSourceConnectionId))
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
            try
            {
                stateChanged |= TryHandleHandshakePacketReceived(
                    new QuicConnectionPacketReceivedEvent(
                        nowTicks,
                        bufferedPacket.PathIdentity,
                        bufferedPacket.Datagram,
                        EcnCounts: bufferedPacket.EcnCounts),
                    nowTicks,
                    allowDeferredBuffering: false,
                    ref effects);
            }
            finally
            {
                bufferedPacket.Dispose();
            }
        }

        return stateChanged;
    }

    private void RemoveBufferedEstablishmentHandshakePacketAt(int index)
    {
        BufferedEstablishmentHandshakePacket bufferedPacket = bufferedEstablishmentHandshakePackets[index];
        bufferedEstablishmentHandshakePackets.RemoveAt(index);
        bufferedPacket.Dispose();
    }

    private void ClearBufferedEstablishmentHandshakePackets()
    {
        foreach (BufferedEstablishmentHandshakePacket bufferedPacket in bufferedEstablishmentHandshakePackets)
        {
            bufferedPacket.Dispose();
        }

        bufferedEstablishmentHandshakePackets.Clear();
    }

    internal bool TryProcessHandshakePacketPayload(
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        out bool packetAckEliciting,
        out bool packetProcessed,
        ref List<QuicConnectionEffect>? effects)
    {
        QuicConnectionEffectAccumulator accumulator = CreateEffectAccumulator(effects);
        bool stateChanged = TryProcessHandshakePacketPayload(
            payload,
            encryptionLevel,
            nowTicks,
            out packetAckEliciting,
            out packetProcessed,
            ref accumulator);
        StoreEffectAccumulator(ref effects, accumulator);
        return stateChanged;
    }

    internal bool TryProcessHandshakePacketPayload(
        ReadOnlySpan<byte> payload,
        QuicTlsEncryptionLevel encryptionLevel,
        long nowTicks,
        out bool packetAckEliciting,
        out bool packetProcessed,
        ref QuicConnectionEffectAccumulator effects)
    {
        packetAckEliciting = false;
        packetProcessed = false;
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
                packetAckEliciting = true;
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

                try
                {
                    stateChanged |= HandleAckFrame(
                        packetNumberSpace,
                        ackFrame,
                        nowTicks,
                        ref effects);
                }
                finally
                {
                    ackFrame.Dispose();
                }

                payloadOffset += ackBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseConnectionCloseFrame(
                    remaining,
                    out QuicConnectionCloseFrame connectionCloseFrame,
                    out int connectionCloseBytesConsumed))
            {
                if (connectionCloseBytesConsumed <= 0)
                {
                    return false;
                }

                if (connectionCloseFrame.IsApplicationError)
                {
                    return HandleFatalTlsSignal(
                        nowTicks,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent an application CONNECTION_CLOSE frame in a packet type that is not permitted.",
                        ref effects);
                }

                QuicConnectionCloseMetadata closeMetadata = CreateCloseMetadata(connectionCloseFrame);
                stateChanged |= HandleConnectionCloseFrameReceived(
                    new QuicConnectionConnectionCloseFrameReceivedEvent(
                        nowTicks,
                        closeMetadata),
                    nowTicks,
                    ref effects);
                packetProcessed = true;
                return stateChanged;
            }

            if (!QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int bytesConsumed)
                || bytesConsumed <= 0)
            {
                if (QuicVariableLengthInteger.TryParse(remaining, out ulong frameType, out int frameTypeBytesConsumed)
                    && frameTypeBytesConsumed > 0
                    && QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(frameType))
                {
                    return HandleFatalTlsSignal(
                        nowTicks,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a frame in a packet type that is not permitted.",
                        ref effects);
                }

                return false;
            }

            processedCryptoFrame = true;
            packetAckEliciting = true;
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

            QuicTlsStateUpdateBatch transcriptUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(
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
            bool sawFatalAlert;
                stateChanged |= ApplyTlsStateUpdates(
                    transcriptUpdates,
                    nowTicks,
                    nowTicks,
                    ref effects,
                    true,
                    out sawFatalAlert);

            if (!sawFatalAlert)
            {
                // All non-fatal transcript updates are surfaced through the runtime so newly available
                // crypto material and handshake state can flush immediately.
            }

            payloadOffset += bytesConsumed;
        }

        stateChanged |= TryFlushInitialPackets(ref effects);
        stateChanged |= TryFlushHandshakePackets(ref effects);
        stateChanged |= TryFlushOneRttCryptoPackets(ref effects);
        if (processedCryptoFrame && !progressedTranscript && !replayedDuplicateInitialCrypto)
        {
            stateChanged |= TryReplayOutstandingCryptoAfterDuplicateInitialIngress(
                encryptionLevel,
                nowTicks,
                ref effects);
        }

        if (tlsState.Role == QuicTlsRole.Client
            && encryptionLevel == QuicTlsEncryptionLevel.Handshake
            && progressedTranscript)
        {
            pendingClientHandshakeAckProbeOnPto = false;
        }

        packetProcessed = true;
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
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
    {
        if (IsVersion1ZeroRttPacket(packetReceivedEvent.Datagram))
        {
            return TryHandleZeroRttApplicationPacketReceived(packetReceivedEvent, nowTicks, ref effects);
        }

        if ((phase != QuicConnectionPhase.Active && phase != QuicConnectionPhase.Establishing)
            || activePath is null
            || !tlsState.OneRttReceiveAuthorized)
        {
            return false;
        }

        if (TryStopUsingConnectionForOneRttOpenAeadLimit(
                tlsState.CurrentOneRttOpenKeyLifecycle,
                ref effects))
        {
            return true;
        }

        bool stateChanged = false;
        bool openedWithCurrentOpenMaterial = false;
        bool openedWithRetainedOldOpenMaterial = false;
        ulong expectedApplicationPacketNumber = GetExpectedReceivedPacketNumber(QuicPacketNumberSpace.ApplicationData);
        QuicBufferLease openedPacket = default;
        bool openedPacketOwned = false;
        try
        {
            if (handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacketLease(
                    packetReceivedEvent.Datagram.Span,
                    tlsState.OneRttOpenPacketProtectionMaterial!.Value,
                    expectedApplicationPacketNumber,
                    CanReceiveGreasedQuicBitPackets,
                    out openedPacket,
                    out int payloadOffset,
                    out int payloadLength,
                    out bool keyPhase))
            {
                openedWithCurrentOpenMaterial = true;
                openedPacketOwned = true;
            }
            else
            {
                if (TryStopUsingConnectionForOneRttOpenAeadLimit(
                        tlsState.RetainedOldOneRttOpenKeyLifecycle,
                        ref effects))
                {
                    return true;
                }

                bool oldKeyPhase = false;
                bool openedWithRetainedOldKeys = tlsState.KeyUpdateInstalled
                    && tlsState.CurrentOneRttKeyPhase != 0
                    && tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue
                    && handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacketLease(
                        packetReceivedEvent.Datagram.Span,
                        tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.Value,
                        expectedApplicationPacketNumber,
                        CanReceiveGreasedQuicBitPackets,
                        out openedPacket,
                        out payloadOffset,
                        out payloadLength,
                        out oldKeyPhase)
                    && oldKeyPhase == (((tlsState.CurrentOneRttKeyPhase - 1UL) & 1UL) == 1UL);

                if (openedWithRetainedOldKeys)
                {
                    keyPhase = oldKeyPhase;
                    openedWithRetainedOldOpenMaterial = true;
                    openedPacketOwned = true;
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
                    bool expectedSuccessorKeyPhase =
                        ((tlsState.CurrentOneRttKeyPhase + 1UL) & 1UL) == 1UL;
                    bool installedSuccessor = false;
                    if (!tlsBridgeDriver.TryDeriveOneRttSuccessorPacketProtectionMaterial(
                            out QuicTlsPacketProtectionMaterial derivedSuccessorOpenMaterial,
                            out QuicTlsPacketProtectionMaterial successorProtectMaterial)
                        || !derivedSuccessorOpenMaterial.Matches(successorOpenMaterial)
                        || !handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacketLease(
                            packetReceivedEvent.Datagram.Span,
                            successorOpenMaterial,
                            expectedApplicationPacketNumber,
                            CanReceiveGreasedQuicBitPackets,
                            out openedPacket,
                            out payloadOffset,
                            out payloadLength,
                            out bool successorKeyPhase)
                        || successorKeyPhase != expectedSuccessorKeyPhase)
                    {
                        return stateChanged;
                    }

                    openedPacketOwned = true;
                    if (tlsState.KeyUpdateInstalled)
                    {
                        installedSuccessor = tlsBridgeDriver.TryInstallRepeatedPeerOneRttKeyUpdate(
                            successorOpenMaterial,
                            successorProtectMaterial);
                    }
                    else if (tlsState.CurrentOneRttKeyPhase == 0)
                    {
                        installedSuccessor = tlsBridgeDriver.TryInstallOneRttKeyUpdate(
                            successorOpenMaterial,
                            successorProtectMaterial);
                    }

                    if (!installedSuccessor)
                    {
                        return stateChanged;
                    }

                    keyPhase = expectedSuccessorKeyPhase;
                    stateChanged = true;
                }
            }

        QuicAeadKeyLifecycle? openedKeyLifecycle = openedWithRetainedOldOpenMaterial
            ? tlsState.RetainedOldOneRttOpenKeyLifecycle
            : tlsState.CurrentOneRttOpenKeyLifecycle;
        bool recordedOpeningUse = openedWithRetainedOldOpenMaterial
            ? tlsState.TryRecordRetainedOldOneRttOpeningUse()
            : tlsState.TryRecordCurrentOneRttOpeningUse();
        if (!recordedOpeningUse)
        {
            if (openedKeyLifecycle is null)
            {
                return false;
            }

            _ = StopUsingConnectionForAeadLimit(
                "The connection reached the AEAD integrity limit.",
                ref effects,
                out _);
            return true;
        }

        if (TryStopUsingConnectionForOneRttOpenAeadLimit(openedKeyLifecycle, ref effects))
        {
            return true;
        }

        if (openedWithCurrentOpenMaterial
            && keyPhase != ((tlsState.CurrentOneRttKeyPhase & 1UL) == 1UL))
        {
            return false;
        }

        stateChanged |= TryCompleteServerHandshakeFromOpenedOneRttPacket(nowTicks, ref effects);

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

        if (!TryExpandOpenedApplicationPacketNumber(openedPacket.Span, payloadOffset, out ulong packetNumber))
        {
            if (ApplicationReceiveDebugEnabled)
            {
                Console.Error.WriteLine(
                    $"app-rx packet-number-failed role={tlsState.Role} payloadOffset={payloadOffset} datagram={packetReceivedEvent.Datagram.Length}.");
            }

            return false;
        }

        bool receivedSpinBit = (openedPacket.Span[0] & QuicPacketHeaderBits.SpinBitMask) != 0;
        stateChanged |= TryUpdatePathSpinBitFromReceivedPacket(
            packetReceivedEvent.PathIdentity,
            packetNumber,
            receivedSpinBit,
            ref effects);

        if (openedWithRetainedOldOpenMaterial
            && hasObservedCurrentOneRttKeyPhasePacketNumber
            && observedCurrentOneRttKeyPhase == tlsState.CurrentOneRttKeyPhase
            && packetNumber >= lowestObservedCurrentOneRttKeyPhasePacketNumber)
        {
            return HandleFatalTlsSignal(
                packetReceivedEvent.ObservedAtTicks,
                QuicTransportErrorCode.KeyUpdateError,
                "The peer sent an old-key packet that violated packet-number ordering.",
                ref effects);
        }

        if (!openedWithRetainedOldOpenMaterial
            && tlsState.KeyUpdateInstalled
            && tlsState.CurrentOneRttKeyPhase != 0
            && keyPhase == tlsState.CurrentOneRttKeyPhaseBit
            && TryArmRetainedOldOneRttKeyDiscard(nowTicks, ref effects))
        {
            stateChanged = true;
        }

        bool packetNumberAdvancesTheHighestObservedValue = !hasObservedApplicationPacketNumber
            || packetNumber > largestObservedApplicationPacketNumber;
        bool processedCryptoFrame = false;
        bool processedStreamFrame = false;
        bool processedApplicationAckFrame = false;
        bool applicationSendCreditUpdated = false;
        bool processedMaxStreamsFrame = false;
        bool packetAckEliciting = false;
        ulong originalBidirectionalLimit = streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit;
        ulong originalUnidirectionalLimit = streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit;
        int payloadEnd = payloadOffset + payloadLength;
        bool receivedOnlyProbingFrames = ContainsOnlyProbingFrames(
            openedPacket.Span.Slice(payloadOffset, payloadLength));
        int offset = payloadOffset;

        while (offset < payloadEnd)
        {
            ReadOnlySpan<byte> remaining = openedPacket.Span.Slice(offset, payloadEnd - offset);
            ReadOnlyMemory<byte> remainingMemory = openedPacket.Memory.Slice(offset, payloadEnd - offset);
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

                try
                {
                    stateChanged |= HandleApplicationAckFrame(
                        ackFrame,
                        nowTicks,
                        ref effects);
                }
                finally
                {
                    ackFrame.Dispose();
                }

                processedApplicationAckFrame = true;
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
                    applicationSendCreditUpdated = true;
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
                    applicationSendCreditUpdated = true;
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

            if (QuicPacketFrameLegality.TryReadApplicationFrameType(remaining, out ulong malformedMaxStreamsFrameType)
                && QuicPacketFrameLegality.IsMaxStreamsFrameType(malformedMaxStreamsFrameType))
            {
                return TryHandleApplicationDataFrameError(
                    nowTicks,
                    malformedMaxStreamsFrameType,
                    QuicTransportErrorCode.FrameEncodingError,
                    "The peer sent an invalid MAX_STREAMS frame.",
                    ref effects);
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
                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        QuicPacketFrameLegality.HandshakePacketStreamDataBlockedFrameType,
                        streamDataBlockedErrorCode,
                        "The peer sent a STREAM_DATA_BLOCKED frame that violated receive-side stream state.",
                        ref effects);
                }

                offset += streamDataBlockedBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicFrameCodec.TryParseStreamsBlockedFrame(
                remaining,
                out QuicStreamsBlockedFrame streamsBlockedFrame,
                out int streamsBlockedBytesConsumed))
            {
                if (streamsBlockedBytesConsumed <= 0)
                {
                    return false;
                }

                _ = streamsBlockedFrame;
                offset += streamsBlockedBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicPacketFrameLegality.TryReadApplicationFrameType(remaining, out ulong malformedStreamsBlockedFrameType)
                && QuicPacketFrameLegality.IsStreamsBlockedFrameType(malformedStreamsBlockedFrameType))
            {
                return TryHandleApplicationDataFrameError(
                    nowTicks,
                    malformedStreamsBlockedFrameType,
                    QuicTransportErrorCode.FrameEncodingError,
                    "The peer sent an invalid STREAMS_BLOCKED frame.",
                    ref effects);
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

                QuicTlsStateUpdateBatch transcriptUpdates = tlsBridgeDriver.AdvanceHandshakeTranscript(
                    QuicTlsEncryptionLevel.OneRtt);
                stateChanged |= ApplyTlsStateUpdates(
                    transcriptUpdates,
                    nowTicks,
                    nowTicks,
                    ref effects);

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

                if (tlsState.Role == QuicTlsRole.Server)
                {
                    return TryHandleInvalidNewTokenFrameReceived(
                        nowTicks,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The server received a NEW_TOKEN frame.",
                        ref effects);
                }

                offset += newTokenBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicPacketFrameLegality.TryReadApplicationFrameType(remaining, out ulong frameType)
                && frameType == QuicPacketFrameLegality.HandshakePacketNewTokenFrameType)
            {
                QuicTransportErrorCode newTokenErrorCode = tlsState.Role == QuicTlsRole.Server
                    ? QuicTransportErrorCode.ProtocolViolation
                    : QuicTransportErrorCode.FrameEncodingError;

                return TryHandleInvalidNewTokenFrameReceived(
                    nowTicks,
                    newTokenErrorCode,
                    "The peer sent an invalid NEW_TOKEN frame.",
                    ref effects);
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

                if (!TryHandleRetireConnectionIdFrame(
                        retireConnectionIdFrame,
                        packetReceivedEvent.RoutedLocallyIssuedConnectionId,
                        nowTicks,
                        ref effects))
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

                if (!TryHandleResetStreamFrame(resetStreamFrame, nowTicks, ref effects))
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

                if (!candidatePath.Validation.ChallengePayload.Span.SequenceEqual(pathResponseFrame.Data)
                    && !candidatePath.Validation.PreviousChallengePayload.Span.SequenceEqual(pathResponseFrame.Data))
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

            if (QuicFrameCodec.TryParseDatagramFrame(remainingMemory, out QuicDatagramFrame datagramFrame, out int datagramBytesConsumed))
            {
                if (datagramBytesConsumed <= 0)
                {
                    return false;
                }

                if (tlsState.LocalTransportParameters?.MaxDatagramFrameSize is not ulong localMaxDatagramFrameSize
                    || localMaxDatagramFrameSize == 0)
                {
                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        datagramFrame.FrameType,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a DATAGRAM frame when local DATAGRAM receive support was not advertised.",
                        ref effects);
                }

                if ((ulong)datagramBytesConsumed > localMaxDatagramFrameSize)
                {
                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        datagramFrame.FrameType,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a DATAGRAM frame larger than the advertised max_datagram_frame_size.",
                        ref effects);
                }

                if (TryQueueInboundDatagram(datagramFrame.DatagramData, out ReadOnlyMemory<byte> queuedDatagram))
                {
                    AppendEffect(
                        ref effects,
                        new QuicConnectionDeliverDatagramEffect(
                            packetReceivedEvent.PathIdentity,
                            queuedDatagram,
                            datagramFrame.FrameType));
                }

                stateChanged = true;
                offset += datagramBytesConsumed;
                packetAckEliciting = true;
                continue;
            }

            if (QuicPacketFrameLegality.TryReadApplicationFrameType(remaining, out ulong malformedDatagramFrameType)
                && QuicPacketFrameLegality.IsDatagramFrameType(malformedDatagramFrameType))
            {
                return TryHandleApplicationDataFrameError(
                    nowTicks,
                    malformedDatagramFrameType,
                    QuicTransportErrorCode.FrameEncodingError,
                    "The peer sent an invalid DATAGRAM frame.",
                    ref effects);
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
            _ = streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                streamFrame.StreamId.Value,
                out QuicConnectionStreamSnapshot previousStreamSnapshot);
            if (!streamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode, QuicApplicationDataEpoch.OneRtt))
            {
                if (ApplicationReceiveRejectDiagnosticsEnabled)
                {
                    _ = streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                        streamFrame.StreamId.Value,
                        out QuicConnectionStreamSnapshot rejectedStreamSnapshot);
                    ulong rejectedFrameEndOffset = streamFrame.Offset + (ulong)streamFrame.StreamDataLength;
                    string rejectionReason = ClassifyStreamFrameRejection(
                        streamFrame,
                        rejectedFrameEndOffset,
                        errorCode,
                        rejectedStreamSnapshot,
                        streamRegistry.Bookkeeping.ConnectionReceiveLimit,
                        streamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
                    Console.Error.WriteLine(
                        $"app-rx stream-rejected role={tlsState.Role} packet={packetNumber} stream={streamFrame.StreamId.Value} " +
                        $"offset={streamFrame.Offset} length={streamFrame.StreamDataLength} end={rejectedFrameEndOffset} fin={streamFrame.IsFin} " +
                        $"error={errorCode} reason={rejectionReason} streamReceiveLimit={rejectedStreamSnapshot.ReceiveLimit} " +
                        $"streamReadOffset={rejectedStreamSnapshot.ReadOffset} " +
                        $"streamAccounted={rejectedStreamSnapshot.AccountedBytesReceived} streamBuffered={rejectedStreamSnapshot.BufferedReadableBytes} " +
                        $"connectionReceiveLimit={streamRegistry.Bookkeeping.ConnectionReceiveLimit} " +
                        $"connectionAccounted={streamRegistry.Bookkeeping.ConnectionAccountedBytesReceived}.");
                }

                return TryHandleApplicationDataFrameError(
                    nowTicks,
                    streamFrame.FrameType,
                    errorCode,
                    "The peer sent a STREAM frame that violated receive-side stream or flow-control state.",
                    ref effects);
            }
            if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                    streamFrame.StreamId.Value,
                    out QuicConnectionStreamSnapshot updatedStreamSnapshot)
                && updatedStreamSnapshot.ReceiveState == QuicStreamReceiveState.DataRecvd)
            {
                _ = sendRuntime.TrySuppressStopSendingRetransmissionForStream(streamFrame.StreamId.Value);
            }

                if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                        streamFrame.StreamId.Value,
                        out QuicConnectionStreamSnapshot updatedReadableSnapshot)
                    && !previousStreamSnapshot.HasContiguousReadableBytes
                    && (updatedReadableSnapshot.HasContiguousReadableBytes
                        || updatedReadableSnapshot.ReceiveState == QuicStreamReceiveState.DataRecvd
                        || updatedReadableSnapshot.ReceiveState == QuicStreamReceiveState.DataRead))
                {
                    NotifyStreamObservers(
                        streamFrame.StreamId.Value,
                        new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null));
                }

            if (streamRegistry.Bookkeeping.TryMarkPeerAcceptQueued(streamFrame.StreamId.Value))
            {
                TryQueueInboundStreamId(streamFrame.StreamId.Value);
            }

            stateChanged = true;
            offset += streamFrame.ConsumedLength;
            packetAckEliciting = true;
        }

        if (packetNumberAdvancesTheHighestObservedValue
            && !receivedOnlyProbingFrames
            && activePath is not null
            && !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(
                activePath.Value.Identity,
                packetReceivedEvent.PathIdentity)
            && TryMarkCandidatePathReadyForNonProbingTraffic(
                packetReceivedEvent.PathIdentity,
                packetNumber,
                nowTicks))
        {
            stateChanged = true;
        }

        if (processedMaxStreamsFrame)
        {
            int bidirectionalIncrement = QuicTransportParameterCommitHelper.GetPositiveIncrement(
                originalBidirectionalLimit,
                streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit);
            int unidirectionalIncrement = QuicTransportParameterCommitHelper.GetPositiveIncrement(
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

        if (processedApplicationAckFrame || applicationSendCreditUpdated)
        {
            stateChanged |= TryRetryPendingStreamWriteRequests(nowTicks, ref effects);
            if (TryFlushPendingApplicationSendsAfterRecoveryProgress(nowTicks, ref effects))
            {
                stateChanged = true;
            }
        }

        RecordIncomingPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            packetAckEliciting,
            nowTicks,
            packetReceivedEvent.EcnCounts);

        UpdateObservedPacketNumber(QuicPacketNumberSpace.ApplicationData, packetNumber);
        if (!openedWithRetainedOldOpenMaterial
            && tlsState.KeyUpdateInstalled
            && tlsState.CurrentOneRttKeyPhase != 0
            && keyPhase == tlsState.CurrentOneRttKeyPhaseBit)
        {
            lowestObservedCurrentOneRttKeyPhasePacketNumber = hasObservedCurrentOneRttKeyPhasePacketNumber
                && observedCurrentOneRttKeyPhase == tlsState.CurrentOneRttKeyPhase
                ? Math.Min(lowestObservedCurrentOneRttKeyPhasePacketNumber, packetNumber)
                : packetNumber;
            observedCurrentOneRttKeyPhase = tlsState.CurrentOneRttKeyPhase;
            hasObservedCurrentOneRttKeyPhasePacketNumber = true;
        }

        if (TrySendPendingApplicationAck(nowTicks, ref effects))
        {
            stateChanged = true;
        }

        if (UpdateApplicationAckDelayTimer(nowTicks))
        {
            stateChanged = true;
            AppendLifecycleTimerEffects(ref effects);
        }

        stateChanged |= TryHandlePreviouslyUnusedIssuedConnectionId(packetReceivedEvent, ref effects);

        return processedStreamFrame || processedCryptoFrame || stateChanged;
        }
        finally
        {
            if (openedPacketOwned)
            {
                openedPacket.Dispose();
            }
        }
    }

    private bool TryCompleteServerHandshakeFromOpenedOneRttPacket(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (tlsState.Role != QuicTlsRole.Server
            || peerHandshakeTranscriptCompleted
            || phase != QuicConnectionPhase.Establishing
            || !tlsState.OneRttReceiveAuthorized)
        {
            return false;
        }

        // Opening a protected 1-RTT packet proves the peer has completed the TLS flight far enough for
        // application data. Promote through the same path as an explicit TLS transcript-complete event so
        // listener acceptance, HANDSHAKE_DONE emission, key discard, and path validation remain coupled.
        return HandlePeerHandshakeTranscriptCompleted(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(nowTicks),
            nowTicks,
            ref effects);
    }

    private bool TryHandleZeroRttApplicationPacketReceived(
        QuicConnectionPacketReceivedEvent packetReceivedEvent,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || tlsState.Role != QuicTlsRole.Server
            || activePath is null
            || !IsEarlyDataAdmissionOpen
            || !tlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out QuicTlsPacketProtectionMaterial zeroRttOpenMaterial))
        {
            return false;
        }

        bool stateChanged = false;
        bool processedStreamFrame = false;
        bool packetAckEliciting = false;
        QuicBufferLease openedPacket = default;
        bool openedPacketOwned = false;
        try
        {
            if (!handshakeFlowCoordinator.TryOpenProtectedZeroRttApplicationDataPacketLease(
                    packetReceivedEvent.Datagram.Span,
                    zeroRttOpenMaterial,
                    out openedPacket,
                    out int payloadOffset,
                    out int payloadLength))
            {
                return false;
            }

            openedPacketOwned = true;
            if (!TryExpandOpenedApplicationPacketNumber(openedPacket.Span, payloadOffset, out ulong packetNumber))
            {
                return false;
            }

            int payloadEnd = payloadOffset + payloadLength;
            int offset = payloadOffset;
            while (offset < payloadEnd)
            {
                ReadOnlySpan<byte> remaining = openedPacket.Span.Slice(offset, payloadEnd - offset);
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

                if (QuicFrameCodec.TryConsumeAckFrame(remaining, out int ackBytesConsumed))
                {
                    if (ackBytesConsumed <= 0)
                    {
                        return false;
                    }

                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        QuicPacketFrameLegality.ApplicationPacketAckFrameType,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent an ACK frame in a 0-RTT packet.",
                        ref effects);
                }

                if (QuicFrameCodec.TryParseCryptoFrame(remaining, out _, out int cryptoBytesConsumed))
                {
                    if (cryptoBytesConsumed <= 0)
                    {
                        return false;
                    }

                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        QuicPacketFrameLegality.ApplicationPacketCryptoFrameType,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a CRYPTO frame in a 0-RTT packet.",
                        ref effects);
                }

                if (QuicFrameCodec.TryParseNewTokenFrame(remaining, out _, out int newTokenBytesConsumed))
                {
                    if (newTokenBytesConsumed <= 0)
                    {
                        return false;
                    }

                    return TryHandleInvalidNewTokenFrameReceived(
                        nowTicks,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a NEW_TOKEN frame in a 0-RTT packet.",
                        ref effects);
                }

                if (QuicFrameCodec.TryParseHandshakeDoneFrame(remaining, out _, out int handshakeDoneBytesConsumed))
                {
                    if (handshakeDoneBytesConsumed <= 0)
                    {
                        return false;
                    }

                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        QuicPacketFrameLegality.HandshakePacketHandshakeDoneFrameType,
                        QuicTransportErrorCode.ProtocolViolation,
                        "The peer sent a HANDSHAKE_DONE frame in a 0-RTT packet.",
                        ref effects);
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

                if (!QuicStreamParser.TryParseStreamFrame(remaining, out QuicStreamFrame streamFrame))
                {
                    return false;
                }

                if (streamFrame.ConsumedLength <= 0)
                {
                    return false;
                }

                _ = streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                    streamFrame.StreamId.Value,
                    out QuicConnectionStreamSnapshot previousStreamSnapshot);
                if (!streamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode, QuicApplicationDataEpoch.ZeroRtt))
                {
                    return TryHandleApplicationDataFrameError(
                        nowTicks,
                        streamFrame.FrameType,
                        errorCode,
                        "The peer sent a STREAM frame that violated receive-side stream or flow-control state.",
                        ref effects);
                }

                if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                        streamFrame.StreamId.Value,
                        out QuicConnectionStreamSnapshot updatedStreamSnapshot)
                    && updatedStreamSnapshot.ReceiveState == QuicStreamReceiveState.DataRecvd)
                {
                    _ = sendRuntime.TrySuppressStopSendingRetransmissionForStream(streamFrame.StreamId.Value);
                }

                if (streamRegistry.Bookkeeping.TryGetStreamSnapshot(
                        streamFrame.StreamId.Value,
                        out QuicConnectionStreamSnapshot updatedReadableSnapshot)
                    && !previousStreamSnapshot.HasContiguousReadableBytes
                    && (updatedReadableSnapshot.HasContiguousReadableBytes
                        || updatedReadableSnapshot.ReceiveState == QuicStreamReceiveState.DataRecvd
                        || updatedReadableSnapshot.ReceiveState == QuicStreamReceiveState.DataRead))
                {
                    NotifyStreamObservers(
                        streamFrame.StreamId.Value,
                        new QuicStreamNotification(QuicStreamNotificationKind.DataAvailable, null));
                }

                if (streamRegistry.Bookkeeping.TryMarkPeerAcceptQueued(streamFrame.StreamId.Value))
                {
                    TryQueueInboundStreamId(streamFrame.StreamId.Value);
                }

                stateChanged = true;
                processedStreamFrame = true;
                offset += streamFrame.ConsumedLength;
                packetAckEliciting = true;
            }

            RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                packetAckEliciting,
                nowTicks,
                packetReceivedEvent.EcnCounts);

            UpdateObservedPacketNumber(QuicPacketNumberSpace.ApplicationData, packetNumber);

            if (TrySendPendingApplicationAck(nowTicks, ref effects))
            {
                stateChanged = true;
            }

            if (UpdateApplicationAckDelayTimer(nowTicks))
            {
                stateChanged = true;
                AppendLifecycleTimerEffects(ref effects);
            }

            stateChanged |= TryHandlePreviouslyUnusedIssuedConnectionId(packetReceivedEvent, ref effects);
            return processedStreamFrame || stateChanged;
        }
        finally
        {
            if (openedPacketOwned)
            {
                openedPacket.Dispose();
            }
        }
    }

    private static bool IsVersion1ZeroRttPacket(ReadOnlyMemory<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(packet.Span, out QuicLongHeaderPacket longHeader)
            && QuicVersionNegotiation.IsSupportedTransportVersion(longHeader.Version)
            && QuicVersionNegotiation.IsLongHeaderPacketType(
                longHeader.Version,
                longHeader.LongPacketTypeBits,
                QuicLongPacketType.ZeroRtt);
    }

    private void RecordIncomingPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        bool ackEliciting,
        long nowTicks,
        QuicEcnCounts? ecnCounts = null)
    {
        sendRuntime.FlowController.RecordIncomingPacket(
            packetNumberSpace,
            packetNumber,
            ackEliciting,
            GetElapsedMicros(nowTicks),
            ecnCounts: ecnCounts);
    }

    private bool TryExpandOpenedPacketNumber(
        ReadOnlySpan<byte> openedPacket,
        int payloadOffset,
        QuicPacketNumberSpace packetNumberSpace,
        out ulong packetNumber)
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

        ulong expectedPacketNumber = GetExpectedReceivedPacketNumber(packetNumberSpace);
        packetNumber = QuicPacketNumberEncoding.ExpandTruncatedPacketNumber(
            truncatedPacketNumber,
            packetNumberLength,
            expectedPacketNumber);
        return true;
    }

    private bool TryExpandOpenedApplicationPacketNumber(
        ReadOnlySpan<byte> openedPacket,
        int payloadOffset,
        out ulong packetNumber)
    {
        return TryExpandOpenedPacketNumber(
            openedPacket,
            payloadOffset,
            QuicPacketNumberSpace.ApplicationData,
            out packetNumber);
    }

    private ulong GetExpectedReceivedPacketNumber(QuicPacketNumberSpace packetNumberSpace)
    {
        return packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => hasObservedInitialPacketNumber
                ? largestObservedInitialPacketNumber + 1
                : 0,
            QuicPacketNumberSpace.Handshake => hasObservedHandshakePacketNumber
                ? largestObservedHandshakePacketNumber + 1
                : 0,
            QuicPacketNumberSpace.ApplicationData => hasObservedApplicationPacketNumber
                ? largestObservedApplicationPacketNumber + 1
                : 0,
            _ => throw new InvalidOperationException($"Unsupported packet number space {packetNumberSpace}."),
        };
    }

    private void UpdateObservedPacketNumber(QuicPacketNumberSpace packetNumberSpace, ulong packetNumber)
    {
        switch (packetNumberSpace)
        {
            case QuicPacketNumberSpace.Initial:
                largestObservedInitialPacketNumber = hasObservedInitialPacketNumber
                    ? Math.Max(largestObservedInitialPacketNumber, packetNumber)
                    : packetNumber;
                hasObservedInitialPacketNumber = true;
                break;
            case QuicPacketNumberSpace.Handshake:
                largestObservedHandshakePacketNumber = hasObservedHandshakePacketNumber
                    ? Math.Max(largestObservedHandshakePacketNumber, packetNumber)
                    : packetNumber;
                hasObservedHandshakePacketNumber = true;
                break;
            case QuicPacketNumberSpace.ApplicationData:
                largestObservedApplicationPacketNumber = hasObservedApplicationPacketNumber
                    ? Math.Max(largestObservedApplicationPacketNumber, packetNumber)
                    : packetNumber;
                hasObservedApplicationPacketNumber = true;
                break;
            default:
                throw new InvalidOperationException($"Unsupported packet number space {packetNumberSpace}.");
        }
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
        ref QuicConnectionEffectAccumulator effects)
    {
        return HandleAckFrame(
            QuicPacketNumberSpace.ApplicationData,
            ackFrame,
            nowTicks,
            ref effects);
    }

    private bool HandleAckFrame(
        QuicPacketNumberSpace packetNumberSpace,
        QuicAckFrame ackFrame,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        ArgumentNullException.ThrowIfNull(ackFrame);

        ulong ackReceivedAtMicros = GetElapsedMicros(nowTicks);
        HashSet<ulong> acknowledgedPacketNumbers = [];
        List<ulong> newlyAcknowledgedAckElicitingPacketNumbers = [];
        bool acknowledgedCurrentOneRttKeyPhasePacket = false;

        foreach (ulong packetNumber in QuicConnectionAckHelpers.EnumerateAcknowledgedPacketNumbers(ackFrame))
        {
            if (!acknowledgedPacketNumbers.Add(packetNumber))
            {
                continue;
            }

            if (sendRuntime.SentPackets.TryGetValue(
                    new QuicConnectionSentPacketKey(packetNumberSpace, packetNumber),
                    out QuicConnectionSentPacket sentPacket))
            {
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

        bool rttSampleUpdated = recoveryController.RecordAcknowledgment(
            packetNumberSpace,
            ackFrame.LargestAcknowledged,
            ackReceivedAtMicros,
            newlyAcknowledgedAckElicitingPacketNumbers.ToArray(),
            ackDelayMicros: ackFrame.AckDelay,
            handshakeConfirmed: HandshakeConfirmed,
            peerMaxAckDelayMicros: tlsState.PeerTransportParameters?.MaxAckDelay ?? 0);
        stateChanged |= rttSampleUpdated;
        if (rttSampleUpdated)
        {
            QuicRttEstimator rttEstimator = recoveryController.GetRttEstimator(packetNumberSpace);
            QuicMetrics.RecordRtt(tlsState.Role, rttEstimator.LatestRttMicros);
        }

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
            AppendLifecycleTimerEffects(ref effects);
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

    private bool TrySendPendingApplicationAck(long nowTicks, ref QuicConnectionEffectAccumulator effects)
    {
        if (activePath is null || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        ulong nowMicros = GetElapsedMicros(nowTicks);
        ulong localMaxAckDelayMicros = GetLocalMaxAckDelayMicros();
        if (!sendRuntime.FlowController.ShouldIncludeAckFrameWithOutgoingPacket(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                localMaxAckDelayMicros)
            || !sendRuntime.FlowController.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros,
                out QuicAckFrame ackFrame)
            || !TryBuildOutboundAckPayloadLease(ackFrame, out QuicBufferLease ackPayload))
        {
            return false;
        }

        try
        {
            if (!TryProtectAndAccountApplicationPayload(
                ackPayload.Memory,
                "The connection runtime could not protect the ACK packet.",
                "The connection cannot send the ACK packet.",
                probePacket: false,
                ackOnlyPacket: true,
                streamIds: null,
                retainPlaintextPayload: false,
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out _))
            {
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };

            MarkApplicationAckFrameSent(
                ackFrame,
                packetNumber: null,
                sentAtMicros: nowMicros,
                ackOnlyPacket: true);

            AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                currentPath.Identity,
                protectedPacket));
            return true;
        }
        finally
        {
            ackPayload.Dispose();
        }
    }

    private bool TrySendPendingClientHandshakeAckProbeWhenNoHandshakeDataInFlight(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || phase != QuicConnectionPhase.Establishing
            || !tlsState.HandshakeKeysAvailable
            || sendRuntime.SentPackets.Values.Any(
                sentPacket => sentPacket.PacketNumberSpace == QuicPacketNumberSpace.Handshake
                    && sentPacket.Retransmittable))
        {
            return false;
        }

        ulong nowMicros = GetElapsedMicros(nowTicks);
        if (!sendRuntime.FlowController.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.Handshake,
            nowMicros,
            maxAckDelayMicros: 0))
        {
            return false;
        }

        bool sent = TrySendLongHeaderAckProbePacket(
            QuicPacketNumberSpace.Handshake,
            nowTicks,
            probePacket: false,
            requireAckFrame: true,
            ref effects);
        if (sent)
        {
            pendingClientHandshakeAckProbeOnPto = true;
        }

        return sent;
    }

    private bool TrySendLongHeaderAckProbePacket(
        QuicPacketNumberSpace packetNumberSpace,
        long nowTicks,
        bool probePacket,
        bool requireAckFrame,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (activePath is null
            || packetNumberSpace is not (QuicPacketNumberSpace.Initial or QuicPacketNumberSpace.Handshake)
            || TryHandlePacketNumberExhaustion(packetNumberSpace, ref effects))
        {
            return false;
        }

        ulong nowMicros = GetElapsedMicros(nowTicks);
        if (!TryBuildLongHeaderAckProbePayload(
            packetNumberSpace,
            nowMicros,
            requireAckFrame,
            out byte[] framePayload,
            out QuicAckFrame? ackFrame))
        {
            return false;
        }

        if (!TryBuildProtectedLongHeaderControlPacket(
            packetNumberSpace,
            framePayload,
            out ulong packetNumber,
            out byte[] protectedPacket))
        {
            return false;
        }

        QuicConnectionActivePathRecord currentPath = activePath.Value;
        if (!currentPath.MaximumDatagramSizeState.CanSendOrdinaryPackets
            || !currentPath.MaximumDatagramSizeState.CanSend((ulong)protectedPacket.Length)
            || !sendRuntime.FlowController.CanSend(
                packetNumberSpace,
                (ulong)protectedPacket.Length,
                isAckOnlyPacket: false,
                isProbePacket: probePacket)
            || !currentPath.AmplificationState.TryConsumeSendBudget(
                protectedPacket.Length,
                out QuicConnectionPathAmplificationState updatedAmplificationState))
        {
            return false;
        }

        activePath = currentPath with
        {
            AmplificationState = updatedAmplificationState,
        };

        TrackLongHeaderAckProbePacket(packetNumberSpace, packetNumber, protectedPacket, probePacket, nowMicros);
        if (ackFrame is not null)
        {
            sendRuntime.FlowController.MarkAckFrameSent(
                packetNumberSpace,
                packetNumber,
                ackFrame,
                nowMicros,
                ackOnlyPacket: false);
        }

        if (diagnosticsEnabled)
        {
            if (packetNumberSpace == QuicPacketNumberSpace.Initial)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(currentPath.Identity, protectedPacket));
            }
            else
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketSent(currentPath.Identity, protectedPacket));
            }
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
            currentPath.Identity,
            protectedPacket));
        return true;
    }

    private bool TryBuildLongHeaderAckProbePayload(
        QuicPacketNumberSpace packetNumberSpace,
        ulong nowMicros,
        bool requireAckFrame,
        out byte[] payload,
        out QuicAckFrame? ackFrame)
    {
        payload = [];
        ackFrame = null;

        byte[] ackPayload = [];
        if (sendRuntime.FlowController.TryBuildAckFrame(packetNumberSpace, nowMicros, out QuicAckFrame builtAckFrame)
            && TryBuildOutboundAckFramePayload(builtAckFrame, out ackPayload))
        {
            ackFrame = builtAckFrame;
        }

        if (requireAckFrame && ackFrame is null)
        {
            return false;
        }

        byte[] buffer = new byte[ackPayload.Length + 1];
        ackPayload.CopyTo(buffer.AsSpan());
        if (!QuicFrameCodec.TryFormatPingFrame(buffer.AsSpan(ackPayload.Length), out int pingBytesWritten)
            || pingBytesWritten <= 0)
        {
            return false;
        }

        payload = buffer.AsSpan(0, ackPayload.Length + pingBytesWritten).ToArray();
        return true;
    }

    private bool TryBuildProtectedLongHeaderControlPacket(
        QuicPacketNumberSpace packetNumberSpace,
        ReadOnlySpan<byte> framePayload,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        packetNumber = default;
        protectedPacket = [];

        return packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => initialPacketProtection is not null
                && handshakeFlowCoordinator.TryBuildProtectedInitialControlPacketForHandshakeDestination(
                    framePayload,
                    initialPacketProtection,
                    out packetNumber,
                    out protectedPacket),
            QuicPacketNumberSpace.Handshake => tlsState.TryGetHandshakeProtectPacketProtectionMaterial(
                    out QuicTlsPacketProtectionMaterial handshakeMaterial)
                && handshakeFlowCoordinator.TryBuildProtectedHandshakeControlPacket(
                    framePayload,
                    handshakeMaterial,
                    out packetNumber,
                    out protectedPacket),
            _ => false,
        };
    }

    private void TrackLongHeaderAckProbePacket(
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumber,
        byte[] protectedPacket,
        bool probePacket,
        ulong sentAtMicros)
    {
        QuicTlsEncryptionLevel encryptionLevel = packetNumberSpace switch
        {
            QuicPacketNumberSpace.Initial => QuicTlsEncryptionLevel.Initial,
            QuicPacketNumberSpace.Handshake => QuicTlsEncryptionLevel.Handshake,
            _ => throw new InvalidOperationException($"Unsupported ACK probe packet number space {packetNumberSpace}."),
        };

        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            (ulong)protectedPacket.Length,
            sentAtMicros,
            AckEliciting: true,
            AckOnlyPacket: false,
            ProbePacket: probePacket,
            Retransmittable: false,
            PacketBytes: protectedPacket,
            PacketProtectionLevel: encryptionLevel));
        recoveryController.RecordPacketSent(
            packetNumberSpace,
            packetNumber,
            sentAtMicros,
            isAckElicitingPacket: true,
            isProbePacket: probePacket,
            packetProtectionLevel: encryptionLevel);

        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(sentAtMicros);
        }
    }

    private bool HandleAckDelayTimerExpired(long nowTicks, ref QuicConnectionEffectAccumulator effects)
    {
        applicationAckState.ClearDueTicks();

        bool sentAck = TrySendPendingApplicationAck(nowTicks, ref effects);
        bool timerUpdated = UpdateApplicationAckDelayTimer(nowTicks);
        AppendLifecycleTimerEffects(ref effects);
        return sentAck || timerUpdated;
    }

    private bool UpdateApplicationAckDelayTimer(long nowTicks)
    {
        ulong nowMicros = GetElapsedMicros(nowTicks);
        return applicationAckState.TryUpdateDueTicks(
            phase,
            activePath is not null && tlsState.OneRttProtectPacketProtectionMaterial.HasValue,
            sendRuntime.FlowController,
            GetLocalMaxAckDelayMicros(),
            nowMicros,
            nowTicks);
    }

    private ulong GetLocalMaxAckDelayMicros()
    {
        return tlsState.LocalTransportParameters?.MaxAckDelay ?? DefaultMaxAckDelayMicros;
    }

    private void MarkApplicationAckFrameSent(
        QuicAckFrame ackFrame,
        ulong? packetNumber,
        ulong sentAtMicros,
        bool ackOnlyPacket)
    {
        applicationAckState.MarkAckFrameSent(
            sendRuntime.FlowController,
            ackFrame,
            packetNumber,
            sentAtMicros,
            ackOnlyPacket);
    }

    private static bool TryBuildOutboundAckPayloadLease(QuicAckFrame ackFrame, out QuicBufferLease payload)
    {
        return QuicConnectionAckHelpers.TryBuildOutboundAckPayloadLease(
            ackFrame,
            ApplicationMinimumProtectedPayloadLength,
            out payload);
    }

    private bool TryBuildLongHeaderAckPiggybackFramePayload(
        QuicPacketNumberSpace packetNumberSpace,
        ulong nowMicros,
        out QuicBufferLease ackFramePayload,
        out int ackFramePayloadLength,
        out QuicAckFrame ackFrame)
    {
        ackFramePayload = default;
        ackFramePayloadLength = 0;
        ackFrame = null!;

        return QuicConnectionAckHelpers.TryBuildLongHeaderAckPiggybackFramePayload(
            packetNumberSpace,
            sendRuntime.FlowController,
            nowMicros,
            out ackFramePayload,
            out ackFramePayloadLength,
            out ackFrame);
    }

    private static bool TryBuildOutboundAckFramePayload(QuicAckFrame ackFrame, out byte[] payload)
    {
        payload = [];

        if (!QuicConnectionAckHelpers.TryBuildOutboundAckPayload(
                ackFrame,
                ApplicationMinimumProtectedPayloadLength,
                out payload))
        {
            return false;
        }
        return true;
    }

    private bool TryHandlePathChallengeFrame(
        QuicConnectionPathIdentity pathIdentity,
        QuicPathChallengeFrame pathChallengeFrame,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        Span<byte> responseFrameBuffer = stackalloc byte[16];
        if (!QuicFrameCodec.TryFormatPathResponseFrame(
            new QuicPathResponseFrame(pathChallengeFrame.Data),
            responseFrameBuffer,
            out int responseFrameBytesWritten))
        {
            return false;
        }

        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            ReadOnlySpan<byte> responseFramePayload = responseFrameBuffer[..responseFrameBytesWritten];
            if (!TryBuildPathValidationDatagram(
                responseFramePayload,
                currentPath.AmplificationState,
                out byte[] responsePayload))
            {
                return false;
            }

            if (tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
            {
                if (!TryProtectAndAccountApplicationPayloadOnPath(
                    pathIdentity,
                    responsePayload,
                    "The connection runtime could not protect the PATH_RESPONSE packet.",
                    "The connection cannot send the PATH_RESPONSE packet.",
                    ref effects,
                    out QuicConnectionPathIdentity actualPathIdentity,
                    out ReadOnlyMemory<byte> protectedPacket,
                    out Exception? exception,
                    retransmittable: false,
                    probePacket: true,
                    includeAckFrame: false))
                {
                    _ = exception;
                    return false;
                }

                activePath = activePath.Value with
                {
                    LastActivityTicks = nowTicks,
                };
                AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(actualPathIdentity, protectedPacket));
                return true;
            }

            if (!TrySendRawPathValidationDatagram(
                pathIdentity,
                responsePayload,
                nowTicks,
                ref effects))
            {
                return false;
            }

            activePath = activePath.Value with
            {
                LastActivityTicks = nowTicks,
            };
            return true;
        }
        else if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            ReadOnlySpan<byte> responseFramePayload = responseFrameBuffer[..responseFrameBytesWritten];
            byte[]? candidatePathChallengePayload = null;
            if (candidatePath.Validation.ChallengePayload.Length != QuicPathValidation.PathChallengeDataLength)
            {
                Span<byte> generatedChallengePayload = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
                if (QuicPathValidation.TryGeneratePathChallengeData(generatedChallengePayload, out int generatedChallengeBytesWritten))
                {
                    candidatePath = candidatePath with
                    {
                        Validation = candidatePath.Validation with
                        {
                            Generation = QuicConnectionTimerDeadlineState.IncrementCounter(candidatePath.Validation.Generation),
                            ChallengeSendCount = candidatePath.Validation.ChallengeSendCount + 1,
                            ChallengeSentAtTicks = nowTicks,
                            ValidationDeadlineTicks = SaturatingAdd(nowTicks, ConvertMicrosToTicks(currentProbeTimeoutMicros)),
                            ChallengePayload = generatedChallengePayload[..generatedChallengeBytesWritten].ToArray(),
                            PreviousChallengePayload = ReadOnlyMemory<byte>.Empty,
                        },
                    };
                    candidatePaths[pathIdentity] = candidatePath;
                }
            }

            if (tlsState.OneRttProtectPacketProtectionMaterial.HasValue
                && candidatePath.Validation.ChallengePayload.Length == QuicPathValidation.PathChallengeDataLength)
            {
                Span<byte> challengeFrameBuffer = stackalloc byte[16];
                if (QuicFrameCodec.TryFormatPathChallengeFrame(
                        new QuicPathChallengeFrame(candidatePath.Validation.ChallengePayload.Span),
                        challengeFrameBuffer,
                        out int challengeFrameBytesWritten))
                {
                    candidatePathChallengePayload =
                    [
                        .. challengeFrameBuffer[..challengeFrameBytesWritten],
                        .. responseFramePayload,
                    ];
                    responseFramePayload = candidatePathChallengePayload;
                }
            }

            if (!TryBuildPathValidationDatagram(
                responseFramePayload,
                candidatePath.AmplificationState,
                out byte[] responsePayload))
            {
                return false;
            }

            if (tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
            {
                if (!TryProtectAndAccountApplicationPayloadOnPath(
                    pathIdentity,
                    responsePayload,
                    "The connection runtime could not protect the PATH_RESPONSE packet.",
                    "The connection cannot send the PATH_RESPONSE packet.",
                    ref effects,
                    out QuicConnectionPathIdentity actualPathIdentity,
                    out ReadOnlyMemory<byte> protectedPacket,
                    out Exception? exception,
                    retransmittable: false,
                    probePacket: true,
                    includeAckFrame: false))
                {
                    _ = exception;
                    return false;
                }

                candidatePath = candidatePaths[pathIdentity];
                candidatePath = candidatePath with
                {
                    LastActivityTicks = nowTicks,
                };
                candidatePaths[pathIdentity] = candidatePath;
                AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(actualPathIdentity, protectedPacket));
                return true;
            }

            if (!TrySendRawPathValidationDatagram(
                pathIdentity,
                responsePayload,
                nowTicks,
                ref effects))
            {
                return false;
            }

            candidatePath = candidatePaths[pathIdentity];
            candidatePath = candidatePath with
            {
                LastActivityTicks = nowTicks,
            };
            candidatePaths[pathIdentity] = candidatePath;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryHandleNewConnectionIdFrame(
        QuicNewConnectionIdFrame newConnectionIdFrame,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects,
        out bool stateChanged)
    {
        stateChanged = false;

        ReadOnlyMemory<byte> currentPeerDestinationConnectionId = CurrentPeerDestinationConnectionId;
        ReadOnlySpan<byte> peerInitialSourceConnectionIdForSequencing =
            GetPeerInitialSourceConnectionIdForSequencing();
        if (peerInitialSourceConnectionIdForSequencing.IsEmpty
            && !currentPeerDestinationConnectionId.IsEmpty)
        {
            peerInitialSourceConnectionIdForSequencing = currentPeerDestinationConnectionId.Span;
        }

        if (!peerConnectionIdState.TryAcceptNewConnectionId(
            newConnectionIdFrame,
            PeerRequestedZeroLengthConnectionId(),
            GetLocalActiveConnectionIdLimit(),
            peerInitialSourceConnectionIdForSequencing,
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers))
        {
            _ = HandleFatalTlsSignal(
                nowTicks,
                errorCode,
                "The peer sent an invalid NEW_CONNECTION_ID frame.",
                ref effects);
            return false;
        }

        if (ActivePath.HasValue)
        {
            peerConnectionIdState.BindCurrentDestinationConnectionIdToPath(ActivePath.Value.Identity);
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
        foreach (ulong retiredSequenceNumber in retiredSequenceNumbers)
        {
            stateChanged |= TrySendRetireConnectionIdFrame(retiredSequenceNumber, ref effects);
        }

        return true;
    }

    private bool TryHandleRetireConnectionIdFrame(
        QuicRetireConnectionIdFrame retireConnectionIdFrame,
        ulong? packetDestinationConnectionIdSequence,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (LocallySelectedZeroLengthConnectionId())
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer retired a connection ID while operating in zero-length destination connection ID mode.",
                ref effects);
        }

        if (retireConnectionIdFrame.SequenceNumber > issuedConnectionIdState.HighestConnectionIdIssuedToPeer)
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer retired an unknown connection ID.",
                ref effects);
        }

        if (packetDestinationConnectionIdSequence.HasValue
            && retireConnectionIdFrame.SequenceNumber == packetDestinationConnectionIdSequence.Value)
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.ProtocolViolation,
                "The peer retired the packet destination connection ID.",
                ref effects);
        }

        if (TryRetireIssuedConnectionId(retireConnectionIdFrame.SequenceNumber, ref effects))
        {
            _ = TryReplenishIssuedConnectionId(ref effects);
        }

        return true;
    }

    private ulong GetLocalActiveConnectionIdLimit()
    {
        return tlsState.LocalTransportParameters?.ActiveConnectionIdLimit
            ?? QuicConnectionPeerConnectionIdState.DefaultActiveConnectionIdLimit;
    }

    private ulong GetPeerActiveConnectionIdLimit()
    {
        return tlsState.PeerTransportParameters?.ActiveConnectionIdLimit
            ?? QuicConnectionPeerConnectionIdState.DefaultActiveConnectionIdLimit;
    }

    private bool TryFlushInitialPackets(
        ref QuicConnectionEffectAccumulator effects,
        bool probePacket = false,
        int maximumDatagrams = int.MaxValue)
    {
        if (phase != QuicConnectionPhase.Establishing
            || initialPacketProtection is null
            || !TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity))
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.Initial, ref effects))
        {
            return true;
        }

        if (retryBootstrapPendingReplay)
        {
            if (retrySourceConnectionId is null
                || retryToken is null
                || initialBootstrapClientHelloBytes is null
                || initialBootstrapClientHelloBytes?.Length == 0)
            {
                return false;
            }

            bool replayed = TryFlushRetriedInitialPackets(
                pathIdentity,
                initialBootstrapClientHelloBytes.HasValue ? initialBootstrapClientHelloBytes.Value.Span : ReadOnlySpan<byte>.Empty,
                retrySourceConnectionId.Value.Span,
                retryToken.Value.Span,
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
            if (!probePacket
                || tlsState.Role != QuicTlsRole.Client
                || initialBootstrapClientHelloBytes is null
                || initialBootstrapClientHelloBytes.Value.Length == 0)
            {
                return false;
            }

            if (retrySourceConnectionId is not null && retryToken is not null)
            {
                return TryFlushRetriedInitialPackets(
                    pathIdentity,
                    initialBootstrapClientHelloBytes.HasValue ? initialBootstrapClientHelloBytes.Value.Span : ReadOnlySpan<byte>.Empty,
                    retrySourceConnectionId.Value.Span,
                    retryToken.Value.Span,
                    initialPacketProtection,
                    probePacket,
                    maximumDatagrams,
                    ref effects);
            }

            ReadOnlySpan<byte> replayInitialToken = initialAddressValidationToken is null
                ? ReadOnlySpan<byte>.Empty
                : initialAddressValidationToken.Value.Span;
            return TryReplayBootstrapInitialPackets(
                pathIdentity,
                initialBootstrapClientHelloBytes.HasValue ? initialBootstrapClientHelloBytes.Value.Span : ReadOnlySpan<byte>.Empty,
                replayInitialToken,
                initialPacketProtection,
                probePacket,
                maximumDatagrams,
                ref effects);
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

            ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
            bool hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
                QuicPacketNumberSpace.Initial,
                nowMicros,
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out QuicAckFrame piggybackedAckFrame);
            byte[] protectedPacket;
            ulong packetNumber;
            bool builtProtectedPacket;
            try
            {
                if (tlsState.Role == QuicTlsRole.Client)
                {
                    ReadOnlySpan<byte> outboundInitialToken = initialAddressValidationToken is null
                        ? ReadOnlySpan<byte>.Empty
                        : initialAddressValidationToken.Value.Span;
                    ReadOnlySpan<byte> destinationConnectionId = GetClientInitialPacketDestinationConnectionId();
                    builtProtectedPacket = handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                        cryptoChunk[..cryptoBytesWritten],
                        cryptoOffset,
                        destinationConnectionId,
                        outboundInitialToken,
                        ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                        initialPacketProtection,
                        out packetNumber,
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
                }
                else
                {
                    builtProtectedPacket = handshakeFlowCoordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
                        cryptoChunk[..cryptoBytesWritten],
                        cryptoOffset,
                        ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                        initialPacketProtection,
                        out packetNumber,
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
                }
            }
            finally
            {
                ackFramePayload.Dispose();
            }

            TrackInitialPacket(packetNumber, protectedPacket, probePacket);
            if (hasPiggybackedAck)
            {
                sendRuntime.FlowController.MarkAckFrameSent(
                    QuicPacketNumberSpace.Initial,
                    packetNumber,
                    piggybackedAckFrame,
                    nowMicros,
                    ackOnlyPacket: false);
            }

            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
            }

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
        ReadOnlySpan<byte> initialToken,
        QuicInitialPacketProtection protection,
        bool probePacket,
        int maximumDatagrams,
        ref QuicConnectionEffectAccumulator effects)
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
            ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
            bool hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
                QuicPacketNumberSpace.Initial,
                nowMicros,
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out QuicAckFrame piggybackedAckFrame);
            ReadOnlySpan<byte> destinationConnectionId = GetClientInitialPacketDestinationConnectionId();
            try
            {
                if (!handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                        cryptoChunk,
                        (ulong)replayOffset,
                        destinationConnectionId,
                        initialToken,
                        ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                        protection,
                        out ulong packetNumber,
                        out byte[] protectedPacket))
                {
                    break;
                }

                TrackInitialPacket(packetNumber, protectedPacket, probePacket);
                if (hasPiggybackedAck)
                {
                    sendRuntime.FlowController.MarkAckFrameSent(
                        QuicPacketNumberSpace.Initial,
                        packetNumber,
                        piggybackedAckFrame,
                        nowMicros,
                        ackOnlyPacket: false);
                }

                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
                }

                AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));

                replayOffset += requestedBytes;
                datagramsSent++;
                stateChanged = true;

                if (datagramsSent >= maximumDatagrams)
                {
                    break;
                }
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }

        return stateChanged;
    }

    private bool TryFlushZeroRttPackets(ref QuicConnectionEffectAccumulator effects)
    {
        if (phase != QuicConnectionPhase.Establishing
            || tlsState.Role != QuicTlsRole.Client
            || zeroRttPacketSent
            || retryBootstrapPendingReplay
            || !HasDormantEarlyDataAttemptReadiness
            || tlsState.OneRttKeysAvailable
            || tlsState.ResumptionAttemptDisposition == QuicTlsResumptionAttemptDisposition.Rejected
            || initialBootstrapClientHelloBytes is null
            || initialBootstrapClientHelloBytes.Value.Length == 0
            || !TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity)
            || !tlsState.TryGetPacketProtectionMaterial(QuicTlsEncryptionLevel.ZeroRtt, out QuicTlsPacketProtectionMaterial packetProtectionMaterial))
        {
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.ApplicationData, ref effects))
        {
            return true;
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
        ref QuicConnectionEffectAccumulator effects)
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
            ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
            bool hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
                QuicPacketNumberSpace.Initial,
                nowMicros,
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out QuicAckFrame piggybackedAckFrame);
            try
            {
                if (!handshakeFlowCoordinator.TryBuildProtectedInitialPacket(
                    cryptoChunk,
                    (ulong)replayOffset,
                    retrySourceConnectionId,
                    retryToken,
                    ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                    protection,
                    out ulong packetNumber,
                    out byte[] protectedPacket))
                {
                    break;
                }

                TrackInitialPacket(packetNumber, protectedPacket, probePacket);
                if (hasPiggybackedAck)
                {
                    sendRuntime.FlowController.MarkAckFrameSent(
                        QuicPacketNumberSpace.Initial,
                        packetNumber,
                        piggybackedAckFrame,
                        nowMicros,
                        ackOnlyPacket: false);
                }

                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.InitialPacketSent(pathIdentity, protectedPacket));
                }

                AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, protectedPacket));
                replayOffset += requestedBytes;
                datagramsSent++;
                stateChanged = true;

                if (datagramsSent >= maximumDatagrams)
                {
                    break;
                }
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }

        return stateChanged;
    }

    private bool TryFlushHandshakePackets(
        ref QuicConnectionEffectAccumulator effects,
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

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.Handshake, ref effects))
        {
            return true;
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

            ulong nowMicros = GetElapsedMicros(lastTransitionTicks);
            bool hasPiggybackedAck = TryBuildLongHeaderAckPiggybackFramePayload(
                QuicPacketNumberSpace.Handshake,
                nowMicros,
                out QuicBufferLease ackFramePayload,
                out int ackFramePayloadLength,
                out QuicAckFrame piggybackedAckFrame);
            try
            {
                if (!handshakeFlowCoordinator.TryBuildProtectedHandshakePacket(
                    cryptoChunk[..cryptoBytesWritten],
                    cryptoOffset,
                    ackFramePayload.Span.Slice(0, ackFramePayloadLength),
                    packetProtectionMaterial,
                    out ulong packetNumber,
                    out byte[] protectedPacket))
                {
                    break;
                }

                if (!TryGetHandshakeOutboundPath(out QuicConnectionPathIdentity pathIdentity)
                    || !TryConsumeHandshakeSendBudget(
                        pathIdentity,
                        protectedPacket.Length,
                        out QuicConnectionPathIdentity sendPathIdentity))
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

                TrackHandshakePacket(packetNumber, protectedPacket, probePacket);
                if (hasPiggybackedAck)
                {
                    sendRuntime.FlowController.MarkAckFrameSent(
                        QuicPacketNumberSpace.Handshake,
                        packetNumber,
                        piggybackedAckFrame,
                        nowMicros,
                        ackOnlyPacket: false);
                }

                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.HandshakePacketSent(sendPathIdentity, protectedPacket));
                }
                AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(
                    sendPathIdentity,
                    protectedPacket));
                stateChanged = true;

                datagramsSent++;
                if (datagramsSent >= maximumDatagrams)
                {
                    break;
                }
            }
            finally
            {
                ackFramePayload.Dispose();
            }
        }

        return stateChanged;
    }

    private bool TryFlushOneRttCryptoPackets(ref QuicConnectionEffectAccumulator effects)
    {
        if (phase != QuicConnectionPhase.Active
            || activePath is null
            || tlsState.OneRttEgressCryptoBuffer.BufferedBytes <= 0
            || !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        bool stateChanged = false;
        Span<byte> cryptoBuffer = stackalloc byte[HandshakeEgressChunkBytes];

        while (tlsState.OneRttEgressCryptoBuffer.BufferedBytes > 0)
        {
            int requestedBytes = Math.Min(cryptoBuffer.Length, tlsState.OneRttEgressCryptoBuffer.BufferedBytes);
            if (requestedBytes <= 0)
            {
                break;
            }

            Span<byte> cryptoChunk = cryptoBuffer[..requestedBytes];
            if (!tlsBridgeDriver.TryPeekOutgoingCryptoData(
                QuicTlsEncryptionLevel.OneRtt,
                cryptoChunk,
                out ulong cryptoOffset,
                out int cryptoBytesWritten)
                || cryptoBytesWritten <= 0)
            {
                break;
            }

            if (!TryBuildOutboundOneRttCryptoPayload(
                cryptoChunk[..cryptoBytesWritten],
                cryptoOffset,
                out byte[] applicationPayload))
            {
                break;
            }

            if (!TryProtectAndAccountApplicationPayload(
                applicationPayload,
                "The connection runtime could not protect the post-handshake CRYPTO packet.",
                "The connection cannot send the post-handshake CRYPTO packet.",
                ref effects,
                out QuicConnectionActivePathRecord currentPath,
                out QuicConnectionPathAmplificationState updatedAmplificationState,
                out ReadOnlyMemory<byte> protectedPacket,
                out Exception? exception))
            {
                _ = exception;
                break;
            }

            if (!tlsBridgeDriver.TryDequeueOutgoingCryptoData(
                QuicTlsEncryptionLevel.OneRtt,
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

    private bool TryFlushHandshakeDonePacket(ref QuicConnectionEffectAccumulator effects)
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
            ref effects,
            out QuicConnectionActivePathRecord currentPath,
            out QuicConnectionPathAmplificationState updatedAmplificationState,
            out ReadOnlyMemory<byte> protectedPacket,
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
        ref QuicConnectionEffectAccumulator effects)
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
        stateChanged |= TryStartPreferredAddressPathValidation(nowTicks, ref effects);
        return stateChanged;
    }

    private bool TryHandleInvalidNewTokenFrameReceived(
        long nowTicks,
        QuicTransportErrorCode errorCode,
        string reasonPhrase,
        ref QuicConnectionEffectAccumulator effects)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: errorCode,
            ApplicationErrorCode: null,
            TriggeringFrameType: QuicPacketFrameLegality.HandshakePacketNewTokenFrameType,
            ReasonPhrase: reasonPhrase);

        return HandleLocalCloseRequested(
            new QuicConnectionLocalCloseRequestedEvent(nowTicks, closeMetadata),
            nowTicks,
            ref effects);
    }

    private bool TryHandleApplicationDataFrameError(
        long nowTicks,
        ulong triggeringFrameType,
        QuicTransportErrorCode errorCode,
        string reasonPhrase,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (errorCode == default)
        {
            return false;
        }

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: errorCode,
            ApplicationErrorCode: null,
            TriggeringFrameType: triggeringFrameType,
            ReasonPhrase: reasonPhrase);

        return HandleLocalCloseRequested(
            new QuicConnectionLocalCloseRequestedEvent(nowTicks, closeMetadata),
            nowTicks,
            ref effects);
    }

    private static string ClassifyStreamFrameRejection(
        QuicStreamFrame streamFrame,
        ulong streamFrameEndOffset,
        QuicTransportErrorCode errorCode,
        QuicConnectionStreamSnapshot streamSnapshot,
        ulong connectionReceiveLimit,
        ulong connectionAccountedBytesReceived)
    {
        if (errorCode != QuicTransportErrorCode.FlowControlError)
        {
            return errorCode.ToString();
        }

        if (streamFrame.IsFin && streamFrameEndOffset > streamSnapshot.ReceiveLimit)
        {
            return "stream-final-size-receive-limit";
        }

        if (streamFrameEndOffset > streamSnapshot.ReceiveLimit)
        {
            return "stream-receive-limit";
        }

        ulong availableConnectionCredit = connectionReceiveLimit > connectionAccountedBytesReceived
            ? connectionReceiveLimit - connectionAccountedBytesReceived
            : 0;
        return availableConnectionCredit == 0
            ? "connection-receive-limit-exhausted"
            : "connection-receive-limit";
    }

    private bool TryFlushNewTokenEmissions(long nowTicks, ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
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
            emissionRecord = new QuicConnectionNewTokenEmissionRecord(pathIdentity, CreateAddressValidationToken(pathIdentity));
            newTokenEmissionsByRemoteAddress.Add(remoteAddress, emissionRecord);
        }

        return TryFlushNewTokenEmission(emissionRecord, nowTicks, ref effects);
    }

    private bool TryFlushNewTokenEmission(
        QuicConnectionNewTokenEmissionRecord emissionRecord,
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
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
            ref effects,
            out QuicConnectionPathIdentity actualPathIdentity,
            out ReadOnlyMemory<byte> protectedPacket,
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

    internal bool TryGetInitialOutboundPath(out QuicConnectionPathIdentity pathIdentity)
    {
        if (TryGetMostRecentUnconfirmedServerCandidatePath(out pathIdentity))
        {
            return true;
        }

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

    internal bool TryGetHandshakeOutboundPath(out QuicConnectionPathIdentity pathIdentity)
    {
        if (TryGetMostRecentUnconfirmedServerCandidatePath(out pathIdentity))
        {
            return true;
        }

        if (activePath is not null)
        {
            pathIdentity = activePath.Value.Identity;
            return true;
        }

        pathIdentity = default;
        return false;
    }

    private bool TryGetMostRecentUnconfirmedServerCandidatePath(out QuicConnectionPathIdentity pathIdentity)
    {
        pathIdentity = default;
        if (tlsState.Role != QuicTlsRole.Server
            || HandshakeConfirmed
            || activePath is null
            || candidatePaths.Count == 0)
        {
            return false;
        }

        long mostRecentActivityTicks = activePath.Value.LastActivityTicks;
        bool found = false;
        foreach (QuicConnectionCandidatePathRecord candidatePath in candidatePaths.Values)
        {
            if (candidatePath.Validation.IsAbandoned
                || candidatePath.LastActivityTicks < mostRecentActivityTicks)
            {
                continue;
            }

            pathIdentity = candidatePath.Identity;
            mostRecentActivityTicks = candidatePath.LastActivityTicks;
            found = true;
        }

        return found;
    }

    private bool TryConsumeHandshakeSendBudget(
        QuicConnectionPathIdentity pathIdentity,
        int protectedPacketLength,
        out QuicConnectionPathIdentity sendPathIdentity)
    {
        sendPathIdentity = default;
        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.AmplificationState.TryConsumeSendBudget(
                    protectedPacketLength,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                return false;
            }

            activePath = currentPath with
            {
                AmplificationState = updatedAmplificationState,
            };
            sendPathIdentity = currentPath.Identity;
            return true;
        }

        if (!TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
            || !candidatePath.AmplificationState.TryConsumeSendBudget(
                protectedPacketLength,
                out QuicConnectionPathAmplificationState updatedCandidateAmplificationState))
        {
            return false;
        }

        candidatePaths[pathIdentity] = candidatePath with
        {
            AmplificationState = updatedCandidateAmplificationState,
        };
        sendPathIdentity = candidatePath.Identity;
        return true;
    }

    private ReadOnlySpan<byte> GetClientInitialPacketDestinationConnectionId()
    {
        ReadOnlySpan<byte> handshakeDestinationConnectionId = handshakeFlowCoordinator.DestinationConnectionId.Span;
        return handshakeDestinationConnectionId.IsEmpty
            ? handshakeFlowCoordinator.InitialDestinationConnectionId.Span
            : handshakeDestinationConnectionId;
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
        ref QuicConnectionEffectAccumulator effects)
    {
        QuicTransportParameters? localTransportParameters = tlsState.LocalTransportParameters;
        if (localTransportParameters is null)
        {
            return false;
        }

        _ = ApplyTransportParameters(
            QuicTransportParameterCommitHelper.CreateLocalTransportParametersCommittedEvent(
                nowTicks,
                localTransportParameters),
            nowTicks,
            ref effects);

        if (tlsState.Role == QuicTlsRole.Server
            && localTransportParameters.PreferredAddress is QuicPreferredAddress preferredAddress)
        {
            _ = TryRegisterPreferredAddressConnectionId(preferredAddress, ref effects);
        }

        ulong maxUdpPayloadSize = localTransportParameters.MaxUdpPayloadSize ?? QuicTransportParameters.DefaultMaxUdpPayloadSize;
        AppendEffect(ref effects, new QuicConnectionUpdateMaxUdpPayloadSizeEffect(maxUdpPayloadSize));
        return true;
    }

    private bool TryRegisterPreferredAddressConnectionId(
        QuicPreferredAddress preferredAddress,
        ref QuicConnectionEffectAccumulator effects)
    {
        if (preferredAddress.ConnectionId is null
            || preferredAddress.StatelessResetToken is null
            || preferredAddress.StatelessResetToken.Length != QuicStatelessReset.StatelessResetTokenLength
            || !QuicConnectionIdKey.TryCreate(preferredAddress.ConnectionId, out _)
            || LocallySelectedZeroLengthConnectionId()
            || !issuedConnectionIdState.CanIssueAnotherConnectionId(MaximumLocallyIssuedConnectionIds)
            || issuedConnectionIdState.StatelessResetTokensByConnectionId.ContainsKey(PreferredAddressConnectionIdSequence)
            || !issuedConnectionIdState.HasRoomForAdditionalPeerIssuedConnectionId(GetPeerActiveConnectionIdLimit())
            || issuedConnectionIdState.IsActiveIssuedConnectionId(preferredAddress.ConnectionId))
        {
            return false;
        }

        byte[] connectionIdBytes = preferredAddress.ConnectionId.ToArray();
        byte[] token = preferredAddress.StatelessResetToken.ToArray();
        if (!issuedConnectionIdState.TryRegisterIssuedConnectionId(
                PreferredAddressConnectionIdSequence,
                connectionIdBytes,
                token,
                GetPeerActiveConnectionIdLimit()))
        {
            return false;
        }

        AppendEffect(ref effects, new QuicConnectionRegisterConnectionIdRouteEffect(PreferredAddressConnectionIdSequence, connectionIdBytes));
        AppendEffect(ref effects, new QuicConnectionRegisterStatelessResetTokenEffect(PreferredAddressConnectionIdSequence, token));
        return true;
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
        ref QuicConnectionEffectAccumulator effects)
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

        QuicTlsStateUpdateBatch updates = tlsBridgeDriver.CommitPeerTransportParameters(
            stagedPeerTransportParameters);
        if (updates.Count == 0)
        {
            return false;
        }

        return ApplyTlsStateUpdates(updates, nowTicks, nowTicks, ref effects);
    }

    private bool TryCommitPeerTransportParametersFromTlsBridgeState(
        long nowTicks,
        ref QuicConnectionEffectAccumulator effects)
    {
        QuicTransportParameters? peerTransportParameters = tlsState.PeerTransportParameters;
        if (peerTransportParameters is null)
        {
            return false;
        }

        QuicTransportParameterRole receiverRole = tlsState.Role == QuicTlsRole.Client
            ? QuicTransportParameterRole.Client
            : QuicTransportParameterRole.Server;

        if (peerTransportParameters.InitialMaxStreamsBidi is > MaximumStreamLimit
            || peerTransportParameters.InitialMaxStreamsUni is > MaximumStreamLimit)
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.TransportParameterError,
                "The peer transport parameters carried an oversized initial max_streams value.",
                ref effects);
        }

        if (receiverRole == QuicTransportParameterRole.Client
            && !QuicTransportParametersCodec.TryValidateServerPreferredAddressConnectionIdConstraints(peerTransportParameters))
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.TransportParameterError,
                "The peer transport parameters carried an invalid preferred_address connection ID.",
                ref effects);
        }

        ReadOnlyMemory<byte> retrySourceConnectionIdSpan = this.retrySourceConnectionId is null
            ? ReadOnlyMemory<byte>.Empty
            : this.retrySourceConnectionId.Value;

        if (peerTransportParameters.VersionInformation is QuicVersionInformation peerVersionInformation)
        {
            if (tlsState.Role == QuicTlsRole.Server)
            {
                uint expectedOriginalVersion = peerInitialPacketProtection?.Version ?? versionProfile.SelectedVersion;
                if (peerVersionInformation.ChosenVersion != expectedOriginalVersion)
                {
                    return DiscardConnection(
                        nowTicks,
                        QuicConnectionCloseOrigin.VersionNegotiation,
                        default,
                        ref effects);
                }
            }
            else
            {
                if (peerVersionInformation.ChosenVersion != versionProfile.SelectedVersion)
                {
                    return DiscardConnection(
                        nowTicks,
                        QuicConnectionCloseOrigin.VersionNegotiation,
                        default,
                        ref effects);
                }

                if (tlsState.LocalTransportParameters?.VersionInformation is QuicVersionInformation localVersionInformation
                    && Array.IndexOf(localVersionInformation.AvailableVersions, peerVersionInformation.ChosenVersion) < 0)
                {
                    return DiscardConnection(
                        nowTicks,
                        QuicConnectionCloseOrigin.VersionNegotiation,
                        default,
                        ref effects);
                }
            }
        }

        bool stateChanged = false;
        if (peerTransportParameters.InitialSourceConnectionId is { Length: 0 })
        {
            stateChanged |= TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte>.Empty);
        }

        ReadOnlySpan<byte> handshakeDestinationConnectionId = handshakeFlowCoordinator.DestinationConnectionId.Span;
        ReadOnlySpan<byte> connectionIdBindingInitialSourceConnectionId = observedPeerInitialSourceConnectionId is null
            ? handshakeDestinationConnectionId
            : observedPeerInitialSourceConnectionId.Value.Span;
        if (!handshakeFlowCoordinator.InitialDestinationConnectionId.IsEmpty
            && !QuicTransportParametersCodec.TryValidateConnectionIdBindings(
                receiverRole,
                handshakeFlowCoordinator.InitialDestinationConnectionId.Span,
                connectionIdBindingInitialSourceConnectionId,
                retrySourceConnectionIdSpan.Length > 0,
                retrySourceConnectionIdSpan.Span,
                peerTransportParameters,
                out QuicConnectionIdBindingValidationError validationError))
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.TransportParameterError,
                $"The peer transport parameters failed connection ID binding validation: {validationError}.",
                ref effects);
        }

        ReadOnlySpan<byte> peerInitialSourceConnectionIdForSequencing =
            GetPeerInitialSourceConnectionIdForSequencing();
        bool preferredAddressConnectionIdChanged = false;
        if (receiverRole == QuicTransportParameterRole.Client
            && peerTransportParameters.PreferredAddress is QuicPreferredAddress preferredAddress
            && !peerConnectionIdState.TryAcceptPreferredAddressConnectionId(
                preferredAddress,
                GetLocalActiveConnectionIdLimit(),
                peerInitialSourceConnectionIdForSequencing,
                out QuicTransportErrorCode preferredAddressErrorCode,
                out preferredAddressConnectionIdChanged))
        {
            return HandleFatalTlsSignal(
                nowTicks,
                preferredAddressErrorCode,
                "The peer transport parameters carried an unusable preferred_address connection ID.",
                ref effects);
        }

        if (receiverRole == QuicTransportParameterRole.Client
            && peerTransportParameters.PreferredAddress is not null
            && preferredAddressConnectionIdChanged
            && !TrySetHandshakeDestinationConnectionId(peerConnectionIdState.CurrentDestinationConnectionId.Span))
        {
            return HandleFatalTlsSignal(
                nowTicks,
                QuicTransportErrorCode.TransportParameterError,
                "The peer preferred_address connection ID could not be installed.",
                ref effects);
        }

        stateChanged |= streamRegistry.Bookkeeping.TryApplyPeerInitialMaxData(
            peerTransportParameters.InitialMaxData ?? 0);

        stateChanged |= streamRegistry.Bookkeeping.TryApplyPeerTransportParameterSendLimits(
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

        stateChanged |= ApplyTransportParameters(
            QuicTransportParameterCommitHelper.CreatePeerTransportParametersCommittedEvent(
                nowTicks,
                peerTransportParameters),
            nowTicks,
            ref effects);
        return stateChanged;
    }

    private ReadOnlySpan<byte> GetPeerInitialSourceConnectionIdForSequencing()
    {
        return observedPeerInitialSourceConnectionId is null
            ? handshakeFlowCoordinator.DestinationConnectionId.Span
            : observedPeerInitialSourceConnectionId.Value.Span;
    }

    private bool HandleTlsKeyDiscard(QuicTlsEncryptionLevel encryptionLevel, ref QuicConnectionEffectAccumulator effects)
    {
        _ = effects;

        bool stateChanged = false;
        switch (encryptionLevel)
        {
            case QuicTlsEncryptionLevel.Initial:
                // Keep ACK history available after Initial keys are discarded so coalesced
                // receive processing can still prove the recorded packet-number-space state.
                stateChanged |= sendRuntime.TryDiscardPacketNumberSpace(
                    QuicPacketNumberSpace.Initial,
                    discardAckGenerationState: false);
                stateChanged |= recoveryController.TryDiscardPacketNumberSpace(
                    QuicPacketNumberSpace.Initial,
                    resetProbeTimeoutBackoff: true);
                break;
            case QuicTlsEncryptionLevel.Handshake:
                // Keep ACK history available after Handshake keys are discarded for the same
                // reason as Initial: the runtime still owns the receipt history even though it
                // can no longer send more long-header packets in that space.
                stateChanged |= sendRuntime.TryDiscardPacketNumberSpace(
                    QuicPacketNumberSpace.Handshake,
                    discardAckGenerationState: false);
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
        ref QuicConnectionEffectAccumulator effects)
    {
        QuicTlsStateUpdateBatch updates = tlsBridgeDriver.PublishKeyDiscard(encryptionLevel);
        if (updates.Count == 0)
        {
            return false;
        }

        return ApplyTlsStateUpdates(updates, nowTicks, nowTicks, ref effects);
    }

    private bool HandleFatalTlsSignal(
        long observedAtTicks,
        QuicTransportErrorCode errorCode,
        string? description,
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects)
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
            AppendLifecycleTimerEffects(ref effects);
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

        bidirectionalIncrement = QuicTransportParameterCommitHelper.GetPositiveIncrement(
            originalBidirectionalLimit,
            streamRegistry.Bookkeeping.PeerBidirectionalStreamLimit);
        unidirectionalIncrement = QuicTransportParameterCommitHelper.GetPositiveIncrement(
            originalUnidirectionalLimit,
            streamRegistry.Bookkeeping.PeerUnidirectionalStreamLimit);

        return stateChanged;
    }

}
