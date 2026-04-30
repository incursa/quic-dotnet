using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic;

// Terminal transitions, lifecycle timers, diagnostics, and shared time/math helpers.
internal sealed partial class QuicConnectionRuntime
{
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

        if (!TryFormatConnectionCloseDatagram(closeMetadata, ref effects, out ReadOnlyMemory<byte> closeDatagram))
        {
            return;
        }

        QuicConnectionActivePathRecord currentPath = activePath.Value;
        if (!currentPath.AmplificationState.TryConsumeSendBudget(
            closeDatagram.Length,
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
            closeDatagram));
    }

    private bool TryFormatConnectionCloseDatagram(
        QuicConnectionCloseMetadata closeMetadata,
        ref List<QuicConnectionEffect>? effects,
        out ReadOnlyMemory<byte> closeDatagram)
    {
        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata);
        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            closeDatagram = closePayload;
            return true;
        }

        if (!TryPrepareOneRttProtectionForAeadLimit(
                "The connection runtime could not protect the CONNECTION_CLOSE packet.",
                ref effects,
                out _))
        {
            closeDatagram = default;
            return false;
        }

        if (handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            closePayload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            out byte[] protectedPacket))
        {
            _ = tlsState.TryRecordCurrentOneRttProtectionUse();
            closeDatagram = protectedPacket;
            return true;
        }

        closeDatagram = default;
        return false;
    }

    private bool TryPrepareOneRttProtectionForAeadLimit(
        string failureMessage,
        ref List<QuicConnectionEffect>? effects,
        out Exception? exception)
    {
        exception = null;
        QuicAeadKeyLifecycle? keyLifecycle = tlsState.CurrentOneRttProtectKeyLifecycle;
        if (keyLifecycle is null)
        {
            return true;
        }

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateProtectionUse(
            keyLifecycle,
            keyUpdatePossible: CanInstallOneRttKeyUpdateForAeadLimit());
        return decision.Action switch
        {
            QuicAeadLimitAction.Continue => true,
            QuicAeadLimitAction.InitiateKeyUpdate
                when TryInstallOneRttKeyUpdateForAeadLimit() => true,
            _ => StopUsingConnectionForAeadLimit(failureMessage, ref effects, out exception),
        };
    }

    private bool TryStopUsingConnectionForOneRttOpenAeadLimit(
        QuicAeadKeyLifecycle? keyLifecycle,
        ref List<QuicConnectionEffect>? effects)
    {
        if (keyLifecycle is null)
        {
            return false;
        }

        QuicAeadLimitDecision decision = QuicAeadLimitPolicy.EvaluateReceivedPacketResponse(
            keyLifecycle,
            connectionStoppedForAeadLimit: false);
        if (!decision.AllowsOnlyStatelessReset)
        {
            return false;
        }

        _ = StopUsingConnectionForAeadLimit(
            "The connection reached the AEAD integrity limit.",
            ref effects,
            out _);
        return true;
    }

    private bool StopUsingConnectionForAeadLimit(
        string reasonPhrase,
        ref List<QuicConnectionEffect>? effects,
        out Exception? exception)
    {
        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.AeadLimitReached,
            ApplicationErrorCode: null,
            TriggeringFrameType: null,
            ReasonPhrase: reasonPhrase);

        _ = DiscardConnection(
            lastTransitionTicks,
            QuicConnectionCloseOrigin.Local,
            closeMetadata,
            ref effects);
        exception = terminalState is QuicConnectionTerminalState terminalStateValue
            ? CreateTerminalException(terminalStateValue)
            : new QuicException(
                QuicError.TransportError,
                null,
                (long)QuicTransportErrorCode.AeadLimitReached,
                reasonPhrase);
        return false;
    }

    private bool CanInstallOneRttKeyUpdateForAeadLimit()
    {
        if (phase != QuicConnectionPhase.Active || !HandshakeConfirmed)
        {
            return false;
        }

        if (!tlsState.KeyUpdateInstalled)
        {
            return tlsState.CurrentOneRttKeyPhase == 0;
        }

        return tlsState.CurrentOneRttKeyPhase != 0
            && tlsState.CanInitiateRepeatedLocalOneRttKeyUpdate(GetElapsedMicros(lastTransitionTicks));
    }

    private bool TryInstallOneRttKeyUpdateForAeadLimit()
    {
        if (!CanInstallOneRttKeyUpdateForAeadLimit())
        {
            return false;
        }

        if (!tlsState.KeyUpdateInstalled)
        {
            return tlsBridgeDriver.TryInstallOneRttKeyUpdate();
        }

        return tlsBridgeDriver.TryInstallRepeatedOneRttKeyUpdate(GetElapsedMicros(lastTransitionTicks));
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
        RefreshCurrentProbeTimeoutMicros(lastTransitionTicks);
        _ = RecomputeIdleTimeoutState(lastTransitionTicks);

        List<QuicConnectionEffect> effects = [];
        long? idleDueTicks = phase switch
        {
            QuicConnectionPhase.Establishing or QuicConnectionPhase.Active when idleTimeoutState is not null
                => GetAbsoluteTicks(idleTimeoutState.IdleTimeoutDeadlineMicros),
            _ => null,
        };

        long? pathValidationDueTicks = GetEarliestPathValidationDueTicks();
        long? recoveryDueTicks = GetEarliestRecoveryDueTicks();
        long? keyUpdateRetentionDueTicks = GetEarliestKeyUpdateRetentionDueTicks();
        long? applicationSendDelayDueTicks = pendingApplicationSendRequests.Count > 0
            ? pendingApplicationSendDelayDueTicks
            : null;
        long? applicationAckDelayDueTicks = GetApplicationAckDelayDueTicks();

        long? closeDueTicks = phase == QuicConnectionPhase.Closing ? terminalEndTicks : null;
        long? drainDueTicks = phase == QuicConnectionPhase.Draining ? terminalEndTicks : null;

        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, idleDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, closeDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.DrainLifetime, drainDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.PathValidation, pathValidationDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.Recovery, recoveryDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.KeyUpdateRetention, keyUpdateRetentionDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.ApplicationSendDelay, applicationSendDelayDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.AckDelay, applicationAckDelayDueTicks));
        return effects.ToArray();
    }

    private long? GetApplicationAckDelayDueTicks()
    {
        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active)
        {
            return null;
        }

        return pendingApplicationAckDelayDueTicks;
    }

    private void RefreshCurrentProbeTimeoutMicros(long nowTicks)
    {
        ulong nowMicros = GetElapsedMicros(nowTicks);
        ulong maxAckDelayMicros = tlsState.PeerTransportParameters?.MaxAckDelay ?? 0;
        bool isHandshakeConfirmed = HandshakeConfirmed;

        if (!recoveryController.TrySelectPtoTimeAndSpace(
                nowMicros,
                maxAckDelayMicros,
                isHandshakeConfirmed,
                tlsState.HandshakeKeysAvailable,
                out ulong selectedProbeTimeoutMicros,
                out _))
        {
            return;
        }

        ulong updatedProbeTimeoutMicros = selectedProbeTimeoutMicros <= nowMicros
            ? 1UL
            : selectedProbeTimeoutMicros - nowMicros;
        if (currentProbeTimeoutMicros == updatedProbeTimeoutMicros)
        {
            return;
        }

        currentProbeTimeoutMicros = updatedProbeTimeoutMicros;
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

    private long? GetEarliestRecoveryDueTicks()
    {
        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active)
        {
            return null;
        }

        if (!TrySelectRecoveryTimer(lastTransitionTicks, out ulong selectedRecoveryTimerMicros, out _))
        {
            return null;
        }

        return GetAbsoluteTicks(selectedRecoveryTimerMicros);
    }

    private long? GetEarliestKeyUpdateRetentionDueTicks()
    {
        if (phase is not QuicConnectionPhase.Establishing and not QuicConnectionPhase.Active
            || !tlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue)
        {
            return null;
        }

        return GetAbsoluteTicks(tlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.Value);
    }

    private bool TryArmRetainedOldOneRttKeyDiscard(long nowTicks, ref List<QuicConnectionEffect>? effects)
    {
        if (!tlsState.RetainedOldOneRttOpenPacketProtectionMaterial.HasValue
            || tlsState.RetainedOldOneRttPacketProtectionDiscardAtMicros.HasValue
            || tlsState.CurrentOneRttKeyPhase == 0)
        {
            return false;
        }

        ulong retentionWindowMicros = MultiplySaturating(Math.Max(currentProbeTimeoutMicros, 1UL), TerminalLifetimePtoMultiplier);
        ulong nowMicros = GetElapsedMicros(nowTicks);
        ulong discardAtMicros = ulong.MaxValue - nowMicros < retentionWindowMicros
            ? ulong.MaxValue
            : nowMicros + retentionWindowMicros;
        if (!tlsState.TryArmRetainedOneRttKeyUpdateMaterialDiscard(
                discardAtMicros,
                tlsState.CurrentOneRttKeyPhase - 1))
        {
            return false;
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
    }

    private bool TryDiscardExpiredRetainedOldOneRttKeyMaterial(ref List<QuicConnectionEffect>? effects)
    {
        if (!tlsState.RetainedOldOneRttPacketProtectionKeyPhase.HasValue)
        {
            return false;
        }

        ulong retainedKeyPhase = tlsState.RetainedOldOneRttPacketProtectionKeyPhase.Value;
        bool stateChanged = tlsState.TryDiscardRetainedOneRttKeyUpdateMaterial();
        stateChanged |= sendRuntime.TryDiscardOneRttKeyPhase(retainedKeyPhase);
        stateChanged |= recoveryController.TryDiscardOneRttKeyPhase(retainedKeyPhase);
        if (!stateChanged)
        {
            return false;
        }

        AppendEffects(ref effects, RecomputeLifecycleTimerEffects());
        return true;
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

    private sealed class QuicConnectionNewTokenEmissionRecord
    {
        internal QuicConnectionNewTokenEmissionRecord(QuicConnectionPathIdentity pathIdentity, byte[] token)
        {
            PathIdentity = pathIdentity;
            Token = token;
        }

        internal QuicConnectionPathIdentity PathIdentity { get; set; }

        internal byte[] Token { get; }

        internal bool IsEmitted { get; set; }
    }

    private void EmitDiagnostic(ref List<QuicConnectionEffect>? effects, QuicDiagnosticEvent diagnosticEvent)
    {
        if (!diagnosticsEnabled)
        {
            return;
        }

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

    private static byte[] CreateAddressValidationToken()
    {
        byte[] token = new byte[NewTokenBytesLength];
        RandomNumberGenerator.Fill(token);
        return token;
    }
}
