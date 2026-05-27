using System.Net;

namespace Incursa.Quic;

// Active-path state, path validation, migration promotion, and recovery resets.
internal sealed partial class QuicConnectionRuntime
{
    private QuicConnectionActivePathRecord? activePath
    {
        get => pathState.ActivePath;
        set => pathState.ActivePath = value;
    }

    private Dictionary<QuicConnectionPathIdentity, QuicConnectionCandidatePathRecord> candidatePaths => pathState.CandidatePaths;

    private Dictionary<QuicConnectionPathIdentity, QuicConnectionValidatedPathRecord> recentlyValidatedPaths => pathState.RecentlyValidatedPaths;

    private string? lastValidatedRemoteAddress
    {
        get => pathState.LastValidatedRemoteAddress;
        set => pathState.LastValidatedRemoteAddress = value;
    }

    private QuicConnectionPathIdentity? preferredAddressOldPathIdentity
    {
        get => pathState.PreferredAddressOldPathIdentity;
        set => pathState.PreferredAddressOldPathIdentity = value;
    }

    internal bool InitializeActivePath(
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

    internal bool TryMarkActivePathValidated(long nowTicks)
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
        ulong? routedLocallyIssuedConnectionId,
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

        if (preferredAddressOldPathIdentity.HasValue
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(preferredAddressOldPathIdentity.Value, pathIdentity))
        {
            return false;
        }

        if (ShouldDiscardUnexpectedServerAddressPacket(
                pathIdentity,
                datagram,
                routedLocallyIssuedConnectionId))
        {
            packetDiscarded = true;
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
                Validation = candidatePath.Validation with
                {
                    ChallengeSendCount = 0,
                    ChallengeSentAtTicks = null,
                    ValidationDeadlineTicks = null,
                },
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

        candidatePaths[pathIdentity] = candidatePath;
        UpdatePeerAddressValidationFlag();

        if (candidatePath.Validation.ChallengeSendCount == 0
            && tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            TrySendPathValidationChallenge(pathIdentity, nowTicks, ref candidatePath, ref effects);
        }

        return stateChanged;
    }

    private bool ShouldDiscardUnexpectedServerAddressPacket(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> datagram,
        ulong? routedLocallyIssuedConnectionId)
    {
        if (tlsState.Role != QuicTlsRole.Client)
        {
            return false;
        }

        if (routedLocallyIssuedConnectionId.HasValue)
        {
            return false;
        }

        if (TryGetCandidatePath(pathIdentity, out _)
            || TryGetRecentlyValidatedPath(pathIdentity, out _))
        {
            return false;
        }

        if (!tlsState.OneRttOpenPacketProtectionMaterial.HasValue
            && !tlsState.OneRttProtectPacketProtectionMaterial.HasValue
            && !tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue
            && !tlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        // Keep bare discovery probes and path-validation probes visible so the runtime can stage
        // or validate a candidate path, but discard actual 1-RTT application packets from a server
        // address the client has not already started validating.
        return (tlsState.OneRttOpenPacketProtectionMaterial.HasValue
                && ShouldDiscardProtectedApplicationDataPacketFromUnexpectedServerAddress(datagram, tlsState.OneRttOpenPacketProtectionMaterial.Value))
            || (tlsState.OneRttProtectPacketProtectionMaterial.HasValue
                && ShouldDiscardProtectedApplicationDataPacketFromUnexpectedServerAddress(datagram, tlsState.OneRttProtectPacketProtectionMaterial.Value))
            || (tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue
                && ShouldDiscardProtectedApplicationDataPacketFromUnexpectedServerAddress(datagram, tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.Value))
            || (tlsState.RetainedOldOneRttProtectPacketProtectionMaterial.HasValue
                && ShouldDiscardProtectedApplicationDataPacketFromUnexpectedServerAddress(datagram, tlsState.RetainedOldOneRttProtectPacketProtectionMaterial.Value));
    }

    private bool ShouldDiscardProtectedApplicationDataPacketFromUnexpectedServerAddress(
        ReadOnlySpan<byte> datagram,
        QuicTlsPacketProtectionMaterial material)
    {
        QuicBufferLease openedPacket = default;
        try
        {
            if (!handshakeFlowCoordinator.TryOpenProtectedApplicationDataPacketLease(
                datagram,
                material,
                GetExpectedReceivedPacketNumber(QuicPacketNumberSpace.ApplicationData),
                CanReceiveGreasedQuicBitPackets,
                out openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out _))
            {
                return false;
            }

            return !ContainsOnlyProbingFrames(openedPacket.Span.Slice(payloadOffset, payloadLength));
        }
        finally
        {
            openedPacket.Dispose();
        }
    }

    private static bool ContainsOnlyProbingFrames(ReadOnlySpan<byte> payload)
    {
        int offset = 0;
        while (offset < payload.Length)
        {
            ReadOnlySpan<byte> remaining = payload[offset..];

            if (QuicFrameCodec.TryParsePaddingFrame(remaining, out int paddingBytesConsumed)
                && paddingBytesConsumed > 0)
            {
                offset += paddingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathChallengeFrame(remaining, out _, out int pathChallengeBytesConsumed)
                && pathChallengeBytesConsumed > 0)
            {
                offset += pathChallengeBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePathResponseFrame(remaining, out _, out int pathResponseBytesConsumed)
                && pathResponseBytesConsumed > 0)
            {
                offset += pathResponseBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParsePingFrame(remaining, out int pingBytesConsumed)
                && pingBytesConsumed > 0)
            {
                offset += pingBytesConsumed;
                continue;
            }

            if (QuicFrameCodec.TryParseNewConnectionIdFrame(remaining, out _, out int newConnectionIdBytesConsumed)
                && newConnectionIdBytesConsumed > 0)
            {
                offset += newConnectionIdBytesConsumed;
                continue;
            }

            return false;
        }

        return true;
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
            ChallengePayload: ReadOnlyMemory<byte>.Empty,
            PreviousChallengePayload: ReadOnlyMemory<byte>.Empty),
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
                ChallengePayload: ReadOnlyMemory<byte>.Empty,
                PreviousChallengePayload: ReadOnlyMemory<byte>.Empty),
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
                ChallengePayload: ReadOnlyMemory<byte>.Empty,
                PreviousChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: null)
        {
            // The client is initiating validation to a server-advertised address; keep path
            // validation separate from server anti-amplification accounting.
            AmplificationState = default(QuicConnectionPathAmplificationState).MarkAddressValidated(),
            MaximumDatagramSizeState = QuicConnectionPathMaximumDatagramSizeState.CreateInitial(),
        };

        candidatePaths[preferredPathIdentity] = candidatePath;
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

        if (tlsState.Role == QuicTlsRole.Client
            && peerHandshakeTranscriptCompleted
            && !tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
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
            out byte[] challengeDatagramPayload))
        {
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.AntiAmplificationBlocked(
                    pathIdentity,
                    (ulong)challengeFrameBytesWritten,
                    candidatePath.AmplificationState.RemainingSendBudget));
            }

            return false;
        }

        if (!TrySendRawPathValidationDatagram(
                pathIdentity,
                challengeDatagramPayload,
                nowTicks,
                ref effects))
        {
            return false;
        }

        if (!TryGetCandidatePath(pathIdentity, out candidatePath))
        {
            return false;
        }

        candidatePath = candidatePath with
        {
            LastActivityTicks = nowTicks,
            Validation = candidatePath.Validation with
            {
                Generation = QuicConnectionTimerDeadlineState.IncrementCounter(candidatePath.Validation.Generation),
                ChallengeSendCount = candidatePath.Validation.ChallengeSendCount + 1,
                ChallengeSentAtTicks = nowTicks,
                ValidationDeadlineTicks = SaturatingAdd(nowTicks, ConvertMicrosToTicks(currentProbeTimeoutMicros)),
                ChallengePayload = challengePayload[..challengePayloadBytesWritten].ToArray(),
                PreviousChallengePayload = candidatePath.Validation.ChallengePayload.Length == QuicPathValidation.PathChallengeDataLength
                    ? candidatePath.Validation.ChallengePayload.ToArray()
                    : ReadOnlyMemory<byte>.Empty,
            },
        };

        candidatePaths[pathIdentity] = candidatePath;
        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.PathValidationChallengeSent(
                pathIdentity,
                candidatePath.Validation.ChallengeSendCount));
        }

        return true;
    }

    private bool TrySendRawPathValidationDatagram(
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlySpan<byte> pathValidationDatagram,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        if (pathValidationDatagram.IsEmpty)
        {
            return false;
        }

        if (!TryUsePeerDestinationConnectionIdOnPath(
                pathIdentity,
                retireInactivePathConnectionIds: false,
                ref effects,
                out Exception? exception))
        {
            _ = exception;
            return false;
        }

        if (TryHandlePacketNumberExhaustion(QuicPacketNumberSpace.ApplicationData, ref effects))
        {
            return false;
        }

        if (!sendRuntime.FlowController.CanSend(
                QuicPacketNumberSpace.ApplicationData,
                (ulong)pathValidationDatagram.Length,
                isAckOnlyPacket: false,
                isProbePacket: true))
        {
            return false;
        }

        if (activePath is not null
            && EqualityComparer<QuicConnectionPathIdentity>.Default.Equals(activePath.Value.Identity, pathIdentity))
        {
            QuicConnectionActivePathRecord currentPath = activePath.Value;
            if (!currentPath.AmplificationState.TryConsumeSendBudget(
                    pathValidationDatagram.Length,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.AntiAmplificationBlocked(
                        pathIdentity,
                        (ulong)pathValidationDatagram.Length,
                        currentPath.AmplificationState.RemainingSendBudget));
                }

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
                    pathValidationDatagram.Length,
                    out QuicConnectionPathAmplificationState updatedAmplificationState))
            {
                if (diagnosticsEnabled)
                {
                    EmitDiagnostic(ref effects, QuicDiagnostics.AntiAmplificationBlocked(
                        pathIdentity,
                        (ulong)pathValidationDatagram.Length,
                        candidatePath.AmplificationState.RemainingSendBudget));
                }

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

        // Path validation probes consume packet numbers and path-local amplification budget,
        // but they intentionally bypass the connection recovery controller so the current
        // path's congestion state remains stable while validation is in flight.
        byte[] rawDatagram = pathValidationDatagram.ToArray();
        if (!handshakeFlowCoordinator.TryReserveApplicationPacketNumber(out _))
        {
            return false;
        }

        ulong sentAtMicros = GetElapsedMicros(lastTransitionTicks);
        if (idleTimeoutState is not null)
        {
            idleTimeoutState.RecordAckElicitingPacketSent(sentAtMicros);
        }

        AppendEffect(ref effects, new QuicConnectionSendDatagramEffect(pathIdentity, rawDatagram));
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
        return pathState.TryGetCandidatePath(pathIdentity, out candidatePath);
    }

    private bool TryMarkCandidatePathReadyForNonProbingTraffic(
        QuicConnectionPathIdentity pathIdentity,
        ulong packetNumber,
        long nowTicks)
    {
        if (!TryGetCandidatePath(pathIdentity, out QuicConnectionCandidatePathRecord candidatePath)
            || candidatePath.Validation.IsAbandoned
            || (candidatePath.HasHighestNonProbingPacketNumber
                && packetNumber <= candidatePath.HighestNonProbingPacketNumber))
        {
            return false;
        }

        candidatePaths[pathIdentity] = candidatePath with
        {
            LastActivityTicks = nowTicks,
            HasHighestNonProbingPacketNumber = true,
            HighestNonProbingPacketNumber = packetNumber,
        };
        return true;
    }

    private bool TryGetPermittedPeerMigrationSendPath(out QuicConnectionPathIdentity pathIdentity)
    {
        pathIdentity = default;
        if (activePath is null || candidatePaths.Count == 0)
        {
            return false;
        }

        ulong selectedPacketNumber = hasObservedApplicationPacketNumber
            ? largestObservedApplicationPacketNumber
            : 0UL;
        bool selected = false;
        foreach (QuicConnectionCandidatePathRecord candidatePath in candidatePaths.Values)
        {
            if (candidatePath.Validation.IsAbandoned
                || !candidatePath.HasHighestNonProbingPacketNumber
                || (hasObservedApplicationPacketNumber
                    && candidatePath.HighestNonProbingPacketNumber < largestObservedApplicationPacketNumber)
                || (selected
                    && candidatePath.HighestNonProbingPacketNumber <= selectedPacketNumber)
                || !CanPromoteActivePathMigration(candidatePath.Identity))
            {
                continue;
            }

            selectedPacketNumber = candidatePath.HighestNonProbingPacketNumber;
            pathIdentity = candidatePath.Identity;
            selected = true;
        }

        return selected;
    }

    private bool TryGetRecentlyValidatedPath(QuicConnectionPathIdentity pathIdentity, out QuicConnectionValidatedPathRecord validatedPath)
    {
        return pathState.TryGetRecentlyValidatedPath(pathIdentity, out validatedPath);
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
        bool receivedSpinBit,
        ref List<QuicConnectionEffect>? effects)
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
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.SpinBitUpdated(pathIdentity, updatedSpinBitState.StoredValue));
            }

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
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.SpinBitUpdated(pathIdentity, updatedSpinBitState.StoredValue));
            }

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
            if (diagnosticsEnabled)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.SpinBitUpdated(pathIdentity, updatedSpinBitState.StoredValue));
            }

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
        pathState.AppendRecentlyValidatedPath(
            pathIdentity,
            nowTicks,
            savedRecoverySnapshot,
            amplificationState,
            maximumDatagramSizeState);
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

        bool accepted = TryApplyProvisionalIcmpMaximumDatagramSizeReduction(
            icmpMaximumDatagramSizeReductionEvent.PathIdentity,
            icmpMaximumDatagramSizeReductionEvent.QuotedPacket.Span,
            icmpMaximumDatagramSizeReductionEvent.MaximumDatagramSizeBytes);

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.IcmpPacketTooBigReceived(
                icmpMaximumDatagramSizeReductionEvent.PathIdentity,
                icmpMaximumDatagramSizeReductionEvent.MaximumDatagramSizeBytes,
                accepted));
            if (accepted)
            {
                EmitDiagnostic(ref effects, QuicDiagnostics.PmtuUpdated(
                    icmpMaximumDatagramSizeReductionEvent.PathIdentity,
                    icmpMaximumDatagramSizeReductionEvent.MaximumDatagramSizeBytes,
                    isProvisional: true));
            }
        }

        return accepted;
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

        if (activePath is not null && activePathChanged)
        {
            if (!preserveCurrentRecoveryState)
            {
                ResetRecoveryStateForNewPath(candidatePath.MaximumDatagramSizeState);
            }
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

        if (diagnosticsEnabled)
        {
            EmitDiagnostic(ref effects, QuicDiagnostics.PathPromoted(pathIdentity, preserveCurrentRecoveryState));
        }

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

        if (activePath is not null)
        {
            if (!preserveCurrentRecoveryState)
            {
                ResetRecoveryStateForNewPath(bestCandidate.Value.MaximumDatagramSizeState);
            }
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
        sendRuntime.TryDiscardPacketNumberSpaceForPathMigration(
            QuicPacketNumberSpace.ApplicationData,
            discardAckGenerationState: false);
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
            && string.Equals(currentPathIdentity.LocalAddress, newPathIdentity.LocalAddress, StringComparison.Ordinal)
            && currentPathIdentity.RemotePort.HasValue
            && newPathIdentity.RemotePort.HasValue
            && currentPathIdentity.LocalPort == newPathIdentity.LocalPort
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

        if (!HandshakeConfirmed
            && activePath is not null
            && string.Equals(activePath.Value.Identity.RemoteAddress, pathIdentity.RemoteAddress, StringComparison.Ordinal)
            && !IsPreferredAddressPath(pathIdentity))
        {
            // Keep same-remote-address migrations on the old path until the client confirms the handshake.
            return false;
        }

        if (PeerRequestedZeroLengthConnectionId()
            && IsLocalAddressChange(pathIdentity))
        {
            return false;
        }

        return !transportFlags.HasFlag(QuicConnectionTransportState.DisableActiveMigration)
            || IsPreferredAddressPath(pathIdentity)
            || !IsLocalAddressChange(pathIdentity);
    }

    private bool IsLocalAddressChange(QuicConnectionPathIdentity pathIdentity)
    {
        return activePath is not null
            && (!string.Equals(activePath.Value.Identity.LocalAddress, pathIdentity.LocalAddress, StringComparison.Ordinal)
                || activePath.Value.Identity.LocalPort != pathIdentity.LocalPort);
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
