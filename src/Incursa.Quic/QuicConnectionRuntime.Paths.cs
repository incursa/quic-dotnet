using System.Net;

namespace Incursa.Quic;

// Active-path state, path validation, migration promotion, and recovery resets.
internal sealed partial class QuicConnectionRuntime
{
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
        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = trustedReuse
            ? recentlyValidatedPath.MaximumDatagramSizeState
            : QuicConnectionPathMaximumDatagramSizeState.CreateInitial();

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
            MaximumDatagramSizeState = maximumDatagramSizeState,
        };

        SyncActivePathMaximumDatagramSize(maximumDatagramSizeState);

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
        if (updatedPath.MaximumDatagramSizeState != path.MaximumDatagramSizeState)
        {
            SyncActivePathMaximumDatagramSize(updatedPath.MaximumDatagramSizeState);
        }

        if (updatedPath.IsValidated)
        {
            lastValidatedRemoteAddress = updatedPath.Identity.RemoteAddress;
        }

        return true;
    }

    private bool TryMarkActivePathValidated(long nowTicks)
    {
        if (activePath is null)
        {
            return false;
        }

        QuicConnectionActivePathRecord currentPath = activePath.Value;
        bool alreadyValidated = currentPath.IsValidated && currentPath.AmplificationState.IsAddressValidated;
        if (alreadyValidated)
        {
            return false;
        }

        QuicConnectionActivePathRecord validatedPath = currentPath with
        {
            IsValidated = true,
            LastActivityTicks = nowTicks,
            AmplificationState = currentPath.AmplificationState.MarkAddressValidated(),
        };

        activePath = validatedPath;
        lastValidatedRemoteAddress = validatedPath.Identity.RemoteAddress;
        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool HandleAddressChangePacket(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        ReadOnlySpan<byte> datagram,
        bool deferTrustedPathReusePromotion,
        ref List<QuicConnectionEffect>? effects,
        out bool packetDiscarded)
    {
        packetDiscarded = false;
        QuicConnectionPathClassification classification = ClassifyPathChange(pathIdentity);
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.AddressChangeClassified(pathIdentity, classification));
        }

        if (ShouldDiscardUnexpectedServerAddressPacket(pathIdentity, datagram))
        {
            packetDiscarded = true;
            return false;
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
            return TryHandleTrustedPathReuse(
                pathIdentity,
                payloadBytes,
                nowTicks,
                recentlyValidatedPath,
                deferTrustedPathReusePromotion,
                ref effects);
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

            if (CanPromoteActivePathMigration(pathIdentity))
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

    private bool ShouldDiscardUnexpectedServerAddressPacket(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> datagram)
    {
        return tlsState.Role == QuicTlsRole.Client
            && phase == QuicConnectionPhase.Active
            && peerHandshakeTranscriptCompleted
            && activePath.HasValue
            && !string.Equals(activePath.Value.Identity.RemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal)
            && !preferredAddressOldPathIdentity.HasValue
            && QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            && packetNumberSpace == QuicPacketNumberSpace.ApplicationData
            && !TryGetCandidatePath(pathIdentity, out _)
            && !TryGetRecentlyValidatedPath(pathIdentity, out _);
    }

    private bool TryHandleTrustedPathReuse(
        QuicConnectionPathIdentity pathIdentity,
        int payloadBytes,
        long nowTicks,
        QuicConnectionValidatedPathRecord recentlyValidatedPath,
        bool deferPromotion,
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
            MaximumDatagramSizeState = recentlyValidatedPath.MaximumDatagramSizeState,
        };

        candidatePaths[pathIdentity] = candidatePath;

        if (deferPromotion)
        {
            UpdatePeerAddressValidationFlag();
            return true;
        }

        AppendRecentlyValidatedPath(
            pathIdentity,
            nowTicks,
            recentlyValidatedPath.SavedRecoverySnapshot,
            candidatePath.AmplificationState,
            candidatePath.MaximumDatagramSizeState);
        lastValidatedRemoteAddress = pathIdentity.RemoteAddress;

        if (CanPromoteActivePathMigration(pathIdentity))
        {
            return TryPromoteValidatedCandidatePath(pathIdentity, nowTicks, ref effects);
        }

        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool ShouldDeferTrustedPathReusePromotion(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> datagram)
    {
        return activePath is not null
            && !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity)
            && TryGetRecentlyValidatedPath(pathIdentity, out _)
            && QuicPacketParser.TryGetPacketNumberSpace(datagram, out QuicPacketNumberSpace packetNumberSpace)
            && packetNumberSpace == QuicPacketNumberSpace.ApplicationData;
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

        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = isTrustedReuse
            ? recentlyValidatedPath!.Value.MaximumDatagramSizeState
            : QuicConnectionPathMaximumDatagramSizeState.CreateInitial();

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
            MaximumDatagramSizeState = maximumDatagramSizeState,
        };

        candidatePaths[pathIdentity] = candidatePath;

        if (!isTrustedReuse)
        {
            TrySendPathValidationChallenge(pathIdentity, nowTicks, ref candidatePath, ref effects);
            candidatePaths[pathIdentity] = candidatePath;
        }
        else
        {
            AppendRecentlyValidatedPath(
                pathIdentity,
                nowTicks,
                recentlyValidatedPath?.SavedRecoverySnapshot,
                candidatePath.AmplificationState,
                candidatePath.MaximumDatagramSizeState);
        }

        if (isTrustedReuse)
        {
            lastValidatedRemoteAddress = pathIdentity.RemoteAddress;
        }

        UpdatePeerAddressValidationFlag();
        return true;
    }

    private bool TryStartPreferredAddressPathValidation(
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (tlsState.Role != QuicTlsRole.Client
            || !HandshakeConfirmed
            || activePath is null
            || PeerRequestedZeroLengthConnectionId()
            || MaximumCandidatePaths == 0
            || tlsState.PeerTransportParameters?.PreferredAddress is not QuicPreferredAddress preferredAddress
            || !TrySelectPreferredAddressPath(
                preferredAddress,
                activePath.Value.Identity,
                out QuicConnectionPathIdentity preferredPathIdentity)
            || EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, preferredPathIdentity))
        {
            return false;
        }

        if (TryGetCandidatePath(preferredPathIdentity, out QuicConnectionCandidatePathRecord existingCandidatePath))
        {
            if (existingCandidatePath.Validation.IsAbandoned
                || existingCandidatePath.Validation.IsValidated
                || (existingCandidatePath.Validation.ValidationDeadlineTicks.HasValue
                    && existingCandidatePath.Validation.ValidationDeadlineTicks.Value > nowTicks))
            {
                return false;
            }

            return TrySendPathValidationChallenge(preferredPathIdentity, nowTicks, ref existingCandidatePath, ref effects);
        }

        if (candidatePaths.Count >= MaximumCandidatePaths)
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.CandidatePathBudgetExhausted(preferredPathIdentity));
            }

            return false;
        }

        QuicConnectionCandidatePathRecord candidatePath = new(
            preferredPathIdentity,
            DiscoveredAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            Validation: new QuicConnectionPathValidationState(
                Generation: 0,
                IsValidated: false,
                IsAbandoned: false,
                ChallengeSendCount: 0,
                ChallengeSentAtTicks: null,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: null)
        {
            // The client is initiating validation to a server-advertised address; keep path
            // validation separate from server anti-amplification accounting.
            AmplificationState = default(QuicConnectionPathAmplificationState).MarkAddressValidated(),
            MaximumDatagramSizeState = QuicConnectionPathMaximumDatagramSizeState.CreateInitial(),
        };

        bool stateChanged = TrySendPathValidationChallenge(
            preferredPathIdentity,
            nowTicks,
            ref candidatePath,
            ref effects);

        UpdatePeerAddressValidationFlag();
        return stateChanged;
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

        if (!TryBuildPathValidationDatagram(
            challengeFrameBuffer[..challengeFrameBytesWritten],
            candidatePath.AmplificationState,
            out byte[] datagram))
        {
            return false;
        }

        if (!candidatePath.AmplificationState.TryConsumeSendBudget(datagram.Length, out QuicConnectionPathAmplificationState updatedAmplificationState))
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

    private static bool TryBuildPathValidationDatagram(
        ReadOnlySpan<byte> pathValidationFrame,
        QuicConnectionPathAmplificationState amplificationState,
        out byte[] datagram)
    {
        datagram = [];

        if (pathValidationFrame.IsEmpty
            || !QuicPathValidation.TryGetPathValidationDatagramPaddingLength(pathValidationFrame.Length, out int paddingLength))
        {
            return false;
        }

        int expandedLength = pathValidationFrame.Length + paddingLength;
        int datagramLength = paddingLength > 0 && amplificationState.CanSend(expandedLength)
            ? expandedLength
            : pathValidationFrame.Length;

        if (!amplificationState.CanSend(datagramLength))
        {
            return false;
        }

        datagram = new byte[datagramLength];
        pathValidationFrame.CopyTo(datagram);

        if (datagramLength == expandedLength && paddingLength > 0)
        {
            if (!QuicPathValidation.TryFormatPathValidationDatagramPadding(
                pathValidationFrame.Length,
                datagram.AsSpan(pathValidationFrame.Length),
                out int paddingBytesWritten)
                || paddingBytesWritten != paddingLength)
            {
                datagram = [];
                return false;
            }
        }

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

    private bool TryGetStoredSpinBitForPath(QuicConnectionPathIdentity pathIdentity, out bool spinBit)
    {
        if (activePath is QuicConnectionActivePathRecord activePathValue
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePathValue.Identity, pathIdentity))
        {
            spinBit = activePathValue.SpinBitState.StoredValue;
            return true;
        }

        if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            spinBit = candidatePath.SpinBitState.StoredValue;
            return true;
        }

        if (TryGetRecentlyValidatedPath(pathIdentity, out QuicConnectionValidatedPathRecord recentlyValidatedPath))
        {
            spinBit = recentlyValidatedPath.SpinBitState.StoredValue;
            return true;
        }

        spinBit = QuicConnectionPathSpinBitState.CreateInitial().StoredValue;
        return false;
    }

    private bool TryUpdatePathSpinBitFromReceivedPacket(
        QuicConnectionPathIdentity pathIdentity,
        ulong packetNumber,
        bool receivedSpinBit)
    {
        if (activePath is QuicConnectionActivePathRecord activePathValue
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePathValue.Identity, pathIdentity))
        {
            if (!activePathValue.SpinBitState.TryUpdateFromReceivedPacket(
                    tlsState.Role,
                    packetNumber,
                    receivedSpinBit,
                    out QuicConnectionPathSpinBitState updatedSpinBitState))
            {
                return false;
            }

            activePath = activePathValue with
            {
                SpinBitState = updatedSpinBitState,
            };
            return true;
        }

        if (TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath))
        {
            if (!candidatePath.SpinBitState.TryUpdateFromReceivedPacket(
                    tlsState.Role,
                    packetNumber,
                    receivedSpinBit,
                    out QuicConnectionPathSpinBitState updatedSpinBitState))
            {
                return false;
            }

            candidatePaths[pathIdentity] = candidatePath with
            {
                SpinBitState = updatedSpinBitState,
            };
            return true;
        }

        if (TryGetRecentlyValidatedPath(pathIdentity, out QuicConnectionValidatedPathRecord recentlyValidatedPath))
        {
            if (!recentlyValidatedPath.SpinBitState.TryUpdateFromReceivedPacket(
                    tlsState.Role,
                    packetNumber,
                    receivedSpinBit,
                    out QuicConnectionPathSpinBitState updatedSpinBitState))
            {
                return false;
            }

            recentlyValidatedPaths[pathIdentity] = recentlyValidatedPath with
            {
                SpinBitState = updatedSpinBitState,
            };
            return true;
        }

        return false;
    }

    private QuicConnectionPathClassification ClassifyPathChange(QuicConnectionPathIdentity pathIdentity)
    {
        if (TryGetRecentlyValidatedPath(pathIdentity, out _))
        {
            return QuicConnectionPathClassification.PreferredAddressTransition;
        }

        if (activePath.HasValue
            && string.Equals(activePath.Value.Identity.RemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal))
        {
            return QuicConnectionPathClassification.MigrationCandidate;
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
        QuicConnectionPathAmplificationState amplificationState,
        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState)
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
            MaximumDatagramSizeState = maximumDatagramSizeState,
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

    private void SyncActivePathMaximumDatagramSize(QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState)
    {
        sendRuntime.FlowController.CongestionControlState.UpdateMaxDatagramSize(
            maximumDatagramSizeState.MaximumDatagramSizeBytes,
            resetToInitialWindow: false);
    }

    internal bool TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> quotedPacket,
        ulong maximumDatagramSizeBytes)
    {
        if (activePath is null
            || !EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity)
            || maximumDatagramSizeBytes < QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes
            || maximumDatagramSizeBytes >= activePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes
            || !TryValidateIcmpQuotedPacket(quotedPacket))
        {
            return false;
        }

        return TrySetActivePathMaximumDatagramSize(maximumDatagramSizeBytes, isProvisional: true);
    }

    private bool HandleIcmpMaximumDatagramSizeReduction(
        QuicConnectionIcmpMaximumDatagramSizeReductionEvent icmpMaximumDatagramSizeReductionEvent,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        _ = nowTicks;
        _ = effects;

        return TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            icmpMaximumDatagramSizeReductionEvent.PathIdentity,
            icmpMaximumDatagramSizeReductionEvent.QuotedPacket.Span,
            icmpMaximumDatagramSizeReductionEvent.MaximumDatagramSizeBytes);
    }

    private bool TryValidateIcmpQuotedPacket(ReadOnlySpan<byte> quotedPacket)
    {
        if (quotedPacket.IsEmpty)
        {
            return false;
        }

        if (QuicPacketParser.TryParseLongHeader(quotedPacket, out QuicLongHeaderPacket longHeader))
        {
            if (longHeader.IsVersionNegotiation)
            {
                return false;
            }

            if (!CurrentPeerDestinationConnectionId.Span.SequenceEqual(longHeader.DestinationConnectionId))
            {
                return false;
            }

            ReadOnlySpan<byte> sourceConnectionId = handshakeFlowCoordinator.SourceConnectionId.Span;
            if (!sourceConnectionId.IsEmpty
                && !sourceConnectionId.SequenceEqual(longHeader.SourceConnectionId))
            {
                return false;
            }

            return true;
        }

        return QuicPacketParser.TryParseShortHeader(quotedPacket, out _);
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

        if (activePathChanged && !CanPromoteActivePathMigration(pathIdentity))
        {
            return false;
        }

        if (activePathChanged
            && !TryUsePeerDestinationConnectionIdOnPath(
                pathIdentity,
                retireInactivePathConnectionIds: false,
                ref effects,
                out _))
        {
            return false;
        }

        if (activePath is not null && activePathChanged && !preserveCurrentRecoveryState)
        {
            ResetRecoveryStateForNewPath(candidatePath.MaximumDatagramSizeState);
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
                activePath.Value.AmplificationState,
                activePath.Value.MaximumDatagramSizeState);
        }

        AppendRecentlyValidatedPath(
            pathIdentity,
            nowTicks,
            candidatePath.SavedRecoverySnapshot,
            candidatePath.AmplificationState,
            candidatePath.MaximumDatagramSizeState);

        QuicConnectionActivePathRecord updatedActivePath = new(
            pathIdentity,
            ActivatedAtTicks: nowTicks,
            LastActivityTicks: nowTicks,
            IsValidated: true,
            RecoverySnapshot: candidatePath.SavedRecoverySnapshot)
        {
            AmplificationState = candidatePath.AmplificationState.MarkAddressValidated(),
            MaximumDatagramSizeState = candidatePath.MaximumDatagramSizeState,
        };

        activePath = updatedActivePath;
        candidatePaths.Remove(pathIdentity);
        lastValidatedRemoteAddress = pathIdentity.RemoteAddress;
        SyncActivePathMaximumDatagramSize(updatedActivePath.MaximumDatagramSizeState);
        UpdatePeerAddressValidationFlag();

        if (activePathChanged)
        {
            _ = TryUsePeerDestinationConnectionIdOnPath(
                pathIdentity,
                retireInactivePathConnectionIds: true,
                ref effects,
                out _);

            AppendEffect(ref effects, new QuicConnectionPromoteActivePathEffect(
                pathIdentity,
                RestoreSavedState: preserveCurrentRecoveryState));
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

            if (!CanPromoteActivePathMigration(entry.Key))
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

        if (!TryUsePeerDestinationConnectionIdOnPath(
                bestPathIdentity.Value,
                retireInactivePathConnectionIds: false,
                ref effects,
                out _))
        {
            return false;
        }

        if (activePath is not null && !preserveCurrentRecoveryState)
        {
            ResetRecoveryStateForNewPath(bestCandidate.Value.MaximumDatagramSizeState);
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
            MaximumDatagramSizeState = bestCandidate.Value.MaximumDatagramSizeState,
        };

        AppendRecentlyValidatedPath(
            bestPathIdentity.Value,
            nowTicks,
            bestCandidate.Value.SavedRecoverySnapshot,
            bestCandidate.Value.AmplificationState,
            bestCandidate.Value.MaximumDatagramSizeState);

        activePath = promotedPath;
        lastValidatedRemoteAddress = bestPathIdentity.Value.RemoteAddress;
        SyncActivePathMaximumDatagramSize(promotedPath.MaximumDatagramSizeState);
        UpdatePeerAddressValidationFlag();
        _ = TryUsePeerDestinationConnectionIdOnPath(
            bestPathIdentity.Value,
            retireInactivePathConnectionIds: true,
            ref effects,
            out _);
        AppendEffect(ref effects, new QuicConnectionPromoteActivePathEffect(
            bestPathIdentity.Value,
            RestoreSavedState: preserveCurrentRecoveryState));
        return true;
    }

    private bool HasPendingPathValidation()
    {
        foreach (QuicConnectionCandidatePathRecord candidatePath in candidatePaths.Values)
        {
            if (!candidatePath.Validation.IsValidated && !candidatePath.Validation.IsAbandoned)
            {
                return true;
            }
        }

        return false;
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

    private void ResetRecoveryStateForNewPath(QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState)
    {
        // A real peer-address change starts the new path with fresh recovery state so stale
        // packets from the old path cannot keep influencing congestion or PTO decisions, but ACK
        // history must survive so previously received packets still drive ACK generation.
        sendRuntime.ResetPathRecoveryState();
        // Recompute the initial congestion window from the promoted path's size, not the path we
        // just abandoned.
        sendRuntime.FlowController.CongestionControlState.UpdateMaxDatagramSize(
            maximumDatagramSizeState.MaximumDatagramSizeBytes,
            resetToInitialWindow: true);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial, discardAckGenerationState: false);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake, discardAckGenerationState: false);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData, discardAckGenerationState: false);
        recoveryController.Reset();
    }

    private void ResetRecoveryStateForRetry()
    {
        // Retry restarts the connection attempt, so discard the sender's packet-number-space
        // recovery state and ACK history while leaving the TLS bridge untouched.
        sendRuntime.ResetPathRecoveryState();
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Initial, discardAckGenerationState: true);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.Handshake, discardAckGenerationState: true);
        sendRuntime.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData, discardAckGenerationState: true);
        largestObservedInitialPacketNumber = 0;
        largestObservedHandshakePacketNumber = 0;
        largestObservedApplicationPacketNumber = 0;
        lowestObservedCurrentOneRttKeyPhasePacketNumber = 0;
        observedCurrentOneRttKeyPhase = 0;
        hasObservedInitialPacketNumber = false;
        hasObservedHandshakePacketNumber = false;
        hasObservedApplicationPacketNumber = false;
        hasObservedCurrentOneRttKeyPhasePacketNumber = false;
        recoveryController.Reset();
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

    private static bool TrySelectPreferredAddressPath(
        QuicPreferredAddress preferredAddress,
        QuicConnectionPathIdentity activePathIdentity,
        out QuicConnectionPathIdentity pathIdentity)
    {
        bool activePathUsesIpv6 =
            IPAddress.TryParse(activePathIdentity.RemoteAddress, out IPAddress? activeAddress)
            && activeAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

        if (activePathUsesIpv6
            && TryCreatePreferredAddressPathIdentity(
                preferredAddress.IPv6Address,
                preferredAddress.IPv6Port,
                activePathIdentity,
                out pathIdentity))
        {
            return true;
        }

        if (!activePathUsesIpv6
            && TryCreatePreferredAddressPathIdentity(
                preferredAddress.IPv4Address,
                preferredAddress.IPv4Port,
                activePathIdentity,
                out pathIdentity))
        {
            return true;
        }

        if (TryCreatePreferredAddressPathIdentity(
                preferredAddress.IPv6Address,
                preferredAddress.IPv6Port,
                activePathIdentity,
                out pathIdentity))
        {
            return true;
        }

        return TryCreatePreferredAddressPathIdentity(
            preferredAddress.IPv4Address,
            preferredAddress.IPv4Port,
            activePathIdentity,
            out pathIdentity);
    }

    private static bool TryCreatePreferredAddressPathIdentity(
        byte[] addressBytes,
        ushort port,
        QuicConnectionPathIdentity activePathIdentity,
        out QuicConnectionPathIdentity pathIdentity)
    {
        pathIdentity = default;

        if (addressBytes.Length is not (PreferredAddressIPv4BytesLength or PreferredAddressIPv6BytesLength)
            || port == 0
            || IsAllZero(addressBytes))
        {
            return false;
        }

        pathIdentity = new QuicConnectionPathIdentity(
            new IPAddress(addressBytes).ToString(),
            activePathIdentity.LocalAddress,
            port,
            activePathIdentity.LocalPort);
        return true;
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        foreach (byte item in value)
        {
            if (item != 0)
            {
                return false;
            }
        }

        return true;
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

    private bool CanPromoteActivePathMigration(QuicConnectionPathIdentity pathIdentity)
    {
        if (!peerHandshakeTranscriptCompleted)
        {
            return false;
        }

        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active)
        {
            return false;
        }

        if (PeerRequestedZeroLengthConnectionId())
        {
            return false;
        }

        return !transportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration)
            || IsPreferredAddressPath(pathIdentity);
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
}
