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
        if (payloadBytes > 0
            && (ulong)payloadBytes > maximumDatagramSizeState.MaximumDatagramSizeBytes)
        {
            maximumDatagramSizeState = maximumDatagramSizeState.WithMaximumDatagramSize((ulong)payloadBytes);
        }

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
        if (payloadBytes > 0
            && (ulong)payloadBytes > updatedPath.MaximumDatagramSizeState.MaximumDatagramSizeBytes)
        {
            updatedPath = updatedPath with
            {
                MaximumDatagramSizeState = updatedPath.MaximumDatagramSizeState.WithMaximumDatagramSize((ulong)payloadBytes),
            };
        }

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
        bool deferTrustedPathReusePromotion,
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

        if (CanPromoteActivePathMigration())
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

        if (activePathChanged && !CanPromoteActivePathMigration())
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
}
