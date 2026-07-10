// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
        Debug.WriteLine($"[QUIC] {nameof(EnterTerminalPhase)} phase={phase}->{nextPhase} origin={origin} reason='{closeMetadata.ReasonPhrase}'");
        phase = nextPhase;
        lifecycleTimerState.UpdateTerminalEndTicks(nowTicks, currentProbeTimeoutMicros, preserveTerminalEndTicks);

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

    private void AppendTerminalEffects(ref QuicConnectionEffectAccumulator effects, bool emitClosePacket)
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
        ref QuicConnectionEffectAccumulator effects,
        QuicConnectionCloseMetadata closeMetadata)
    {
        if (activePath is null)
        {
            return;
        }

        List<ReadOnlyMemory<byte>> closeDatagrams = [];
        if (!TryFormatConnectionCloseDatagrams(closeMetadata, ref effects, closeDatagrams))
        {
            return;
        }

        foreach (ReadOnlyMemory<byte> closeDatagram in closeDatagrams)
        {
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
    }

    private bool TryFormatConnectionCloseDatagrams(
        QuicConnectionCloseMetadata closeMetadata,
        ref QuicConnectionEffectAccumulator effects,
        List<ReadOnlyMemory<byte>> closeDatagrams)
    {
        // CONTEXT: The close path intentionally emits whichever protection level the peer may still be
        // able to decrypt, then falls back to the least-protected payload if no protected datagram can
        // be built. That keeps CONNECTION_CLOSE observable during teardown instead of assuming a single
        // key phase.
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Lifecycle.cs#TryFormatOneRttConnectionCloseDatagram
        // SEE: code:src/Incursa.Quic/QuicConnectionRuntime.Lifecycle.cs#TryFormatInitialConnectionCloseDatagram
        if (HandshakeConfirmed)
        {
            if (TryFormatOneRttConnectionCloseDatagram(closeMetadata, ref effects, out ReadOnlyMemory<byte> oneRttCloseDatagram))
            {
                closeDatagrams.Add(oneRttCloseDatagram);
                return true;
            }

            closeDatagrams.Add(FormatConnectionClosePayload(closeMetadata));
            return true;
        }

        if (TryFormatInitialConnectionCloseDatagram(closeMetadata, out ReadOnlyMemory<byte> initialCloseDatagram))
        {
            closeDatagrams.Add(initialCloseDatagram);
        }

        if (TryFormatHandshakeConnectionCloseDatagram(closeMetadata, out ReadOnlyMemory<byte> handshakeCloseDatagram))
        {
            closeDatagrams.Add(handshakeCloseDatagram);
        }

        if (TryFormatOneRttConnectionCloseDatagram(closeMetadata, ref effects, out ReadOnlyMemory<byte> applicationCloseDatagram))
        {
            closeDatagrams.Add(applicationCloseDatagram);
        }

        if (closeDatagrams.Count == 0)
        {
            closeDatagrams.Add(FormatConnectionClosePayload(closeMetadata, lowerProtectionPacket: true));
        }

        return true;
    }

    private bool TryFormatOneRttConnectionCloseDatagram(
        QuicConnectionCloseMetadata closeMetadata,
        ref QuicConnectionEffectAccumulator effects,
        out ReadOnlyMemory<byte> closeDatagram)
    {
        closeDatagram = default;
        if (!tlsState.OneRttProtectPacketProtectionMaterial.HasValue)
        {
            return false;
        }

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata);
        if (!TryPrepareOneRttProtectionForAeadLimit(
                "The connection runtime could not protect the CONNECTION_CLOSE packet.",
                ref effects,
                out _))
        {
            return false;
        }

        if (handshakeFlowCoordinator.TryBuildProtectedApplicationDataPacket(
            closePayload.Span,
            tlsState.OneRttProtectPacketProtectionMaterial.Value,
            tlsState.CurrentOneRttKeyPhaseBit,
            activePath?.SpinBitState.StoredValue ?? QuicConnectionPathSpinBitState.CreateInitial().StoredValue,
            PeerSupportsGreasedQuicBit,
            out _,
            out byte[] protectedPacket))
        {
            _ = tlsState.TryRecordCurrentOneRttProtectionUse();
            closeDatagram = protectedPacket;
            return true;
        }

        closeDatagram = default;
        return false;
    }

    private bool TryFormatInitialConnectionCloseDatagram(
        QuicConnectionCloseMetadata closeMetadata,
        out ReadOnlyMemory<byte> closeDatagram)
    {
        closeDatagram = default;
        if (tlsState.Role != QuicTlsRole.Server || initialPacketProtection is null)
        {
            return false;
        }

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata, lowerProtectionPacket: true);
        if (!handshakeFlowCoordinator.TryBuildProtectedInitialControlPacketForHandshakeDestination(
            closePayload.Span,
            initialPacketProtection,
            out _,
            out byte[] protectedPacket))
        {
            return false;
        }

        closeDatagram = protectedPacket;
        return true;
    }

    private bool TryFormatHandshakeConnectionCloseDatagram(
        QuicConnectionCloseMetadata closeMetadata,
        out ReadOnlyMemory<byte> closeDatagram)
    {
        closeDatagram = default;
        if (!tlsState.TryGetHandshakeProtectPacketProtectionMaterial(out QuicTlsPacketProtectionMaterial handshakeMaterial))
        {
            return false;
        }

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata, lowerProtectionPacket: true);
        if (!handshakeFlowCoordinator.TryBuildProtectedHandshakeControlPacket(
            closePayload.Span,
            handshakeMaterial,
            out _,
            out byte[] protectedPacket))
        {
            return false;
        }

        closeDatagram = protectedPacket;
        return true;
    }

    private bool TryPrepareOneRttProtectionForAeadLimit(
        string failureMessage,
        ref QuicConnectionEffectAccumulator effects,
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
        ref QuicConnectionEffectAccumulator effects)
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
        ref QuicConnectionEffectAccumulator effects,
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

    private bool TryStopUsingConnectionForPacketNumberExhaustion(
        ref QuicConnectionEffectAccumulator effects)
    {
        if (phase == QuicConnectionPhase.Discarded)
        {
            return false;
        }

        QuicConnectionCloseMetadata closeMetadata = new(
            TransportErrorCode: QuicTransportErrorCode.ProtocolViolation,
            ApplicationErrorCode: null,
            TriggeringFrameType: null,
            ReasonPhrase: "The connection reached the packet number exhaustion limit.");

        _ = DiscardConnection(
            lastTransitionTicks,
            QuicConnectionCloseOrigin.Local,
            closeMetadata,
            ref effects);
        return true;
    }

    private bool TryHandlePacketNumberExhaustion(
        QuicPacketNumberSpace packetNumberSpace,
        ref QuicConnectionEffectAccumulator effects)
    {
        _ = packetNumberSpace;

        if (phase == QuicConnectionPhase.Discarded)
        {
            return true;
        }

        if (!handshakeFlowCoordinator.HasExhaustedPacketNumbers
            && !handshakeFlowCoordinator.HasExhaustedApplicationPacketNumbers)
        {
            return false;
        }

        return TryStopUsingConnectionForPacketNumberExhaustion(ref effects);
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

    internal bool TryInitiateOneRttKeyUpdate()
    {
        if (phase != QuicConnectionPhase.Active
            || !HandshakeConfirmed
            || tlsState.KeyUpdateInstalled)
        {
            return false;
        }

        return tlsBridgeDriver.TryInstallOneRttKeyUpdate();
    }

    internal bool HasObservedOneRttKeyUpdate =>
        tlsState.KeyUpdateInstalled
        && tlsState.CurrentOneRttKeyPhase != 0;

    private static QuicConnectionCloseMetadata CreatePeerConnectionCloseReplyMetadata()
    {
        return new QuicConnectionCloseMetadata(
            TransportErrorCode: QuicTransportErrorCode.NoError,
            ApplicationErrorCode: null,
            TriggeringFrameType: 0x1c,
            ReasonPhrase: null);
    }

    internal QuicConnectionEffect[] RecomputeLifecycleTimerEffects()
    {
        QuicConnectionEffectAccumulator effects = default;
        AppendLifecycleTimerEffects(ref effects);
        return effects.ToArray();
    }

    private void AppendLifecycleTimerEffects(ref QuicConnectionEffectAccumulator effects)
    {
        RefreshCurrentProbeTimeoutMicros(lastTransitionTicks);
        _ = RecomputeIdleTimeoutState(lastTransitionTicks);

        long? idleDueTicks = phase switch
        {
            QuicConnectionPhase.Establishing or QuicConnectionPhase.Active when idleTimeoutState is not null
                => GetAbsoluteTicks(idleTimeoutState.IdleTimeoutDeadlineMicros),
            _ => null,
        };

        long? pathValidationDueTicks = GetEarliestPathValidationDueTicks();
        long? recoveryDueTicks = GetEarliestRecoveryDueTicks();
        long? keyUpdateRetentionDueTicks = GetEarliestKeyUpdateRetentionDueTicks();
        long? applicationSendDelayDueTicks = applicationSendQueue.Count > 0
            ? pendingApplicationSendDelayDueTicks
            : null;
        long? applicationAckDelayDueTicks = GetApplicationAckDelayDueTicks();

        long? closeDueTicks = phase == QuicConnectionPhase.Closing ? lifecycleTimerState.TerminalEndTicks : null;
        long? drainDueTicks = phase == QuicConnectionPhase.Draining ? lifecycleTimerState.TerminalEndTicks : null;

        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.IdleTimeout, idleDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.CloseLifetime, closeDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.DrainLifetime, drainDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.PathValidation, pathValidationDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.Recovery, recoveryDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.KeyUpdateRetention, keyUpdateRetentionDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.ApplicationSendDelay, applicationSendDelayDueTicks);
        AppendTimerDeadlineEffect(ref effects, QuicConnectionTimerKind.AckDelay, applicationAckDelayDueTicks);
    }

    private long? GetApplicationAckDelayDueTicks()
    {
        return applicationAckState.GetDueTicks(phase);
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

    private bool TryArmRetainedOldOneRttKeyDiscard(long nowTicks, ref QuicConnectionEffectAccumulator effects)
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

        AppendLifecycleTimerEffects(ref effects);
        return true;
    }

    private bool TryDiscardExpiredRetainedOldOneRttKeyMaterial(ref QuicConnectionEffectAccumulator effects)
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

        AppendLifecycleTimerEffects(ref effects);
        return true;
    }

    internal ulong GetElapsedMicros(long nowTicks)
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

    private static ReadOnlyMemory<byte> FormatConnectionClosePayload(
        QuicConnectionCloseMetadata closeMetadata,
        bool lowerProtectionPacket = false)
    {
        bool convertApplicationClose = lowerProtectionPacket && closeMetadata.ApplicationErrorCode.HasValue;
        byte[] reasonBytes = closeMetadata.ReasonPhrase is null || convertApplicationClose
            ? []
            : Encoding.UTF8.GetBytes(closeMetadata.ReasonPhrase);

        QuicTransportErrorCode transportErrorCode = convertApplicationClose
            ? QuicTransportErrorCode.ApplicationError
            : closeMetadata.TransportErrorCode ?? QuicTransportErrorCode.NoError;

        QuicConnectionCloseFrame frame = closeMetadata.ApplicationErrorCode.HasValue && !convertApplicationClose
            ? new QuicConnectionCloseFrame(closeMetadata.ApplicationErrorCode.Value, reasonBytes)
            : new QuicConnectionCloseFrame(
                transportErrorCode,
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

    internal sealed class QuicConnectionNewTokenEmissionRecord
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

    private void EmitDiagnostic(ref QuicConnectionEffectAccumulator effects, QuicDiagnosticEvent diagnosticEvent)
    {
        diagnosticsState.EmitDiagnostic(ref effects, diagnosticEvent);
    }

    private void AppendEffect(ref QuicConnectionEffectAccumulator effects, QuicConnectionEffect effect)
    {
        if (effect is QuicConnectionSendDatagramEffect sendDatagramEffect)
        {
            QuicEcnMarking currentEcnMarking = sendRuntime.CurrentEcnMarking;
            if (sendDatagramEffect.EcnMarking != currentEcnMarking)
            {
                effect = sendDatagramEffect with { EcnMarking = currentEcnMarking };
            }
        }

        effects.Add(effect);
    }

    private void AppendSendDatagramEffect(
        ref QuicConnectionEffectAccumulator effects,
        QuicConnectionPathIdentity pathIdentity,
        ReadOnlyMemory<byte> datagram)
    {
        QuicConnectionSendDatagramUpdate update = new(
            pathIdentity,
            datagram,
            sendRuntime.CurrentEcnMarking);
        if (suppressHostedSendDatagramEffectObjects)
        {
            (pendingHostedSendDatagramUpdates ??= new List<QuicConnectionSendDatagramUpdate>(
                InitialHostedSendDatagramUpdateCapacity)).Add(update);
            effects.Add(QuicConnectionHostedSendDatagramMarkerEffect.Instance);
            return;
        }

        effects.Add(update.ToEffect());
    }

    private static QuicConnectionEffectAccumulator CreateEffectAccumulator(List<QuicConnectionEffect>? effects)
    {
        return effects is null ? default : QuicConnectionEffectAccumulator.FromList(effects);
    }

    private static void StoreEffectAccumulator(
        ref List<QuicConnectionEffect>? effects,
        QuicConnectionEffectAccumulator accumulator)
    {
        effects = accumulator.ToList();
    }

    private void AppendTimerDeadlineEffect(
        ref QuicConnectionEffectAccumulator effects,
        QuicConnectionTimerKind timerKind,
        long? dueTicks)
    {
        if (!lifecycleTimerState.TrySetTimerDeadline(timerKind, dueTicks, out QuicConnectionTimerUpdate update))
        {
            return;
        }

        if (suppressHostedTimerEffectObjects)
        {
            (pendingHostedTimerUpdates ??= new List<QuicConnectionTimerUpdate>(InitialHostedTimerUpdateCapacity)).Add(update);
            return;
        }

        AppendEffect(ref effects, update.ToEffect());
    }

    internal void ConfigureHostedTimerEffectSuppression(bool suppress)
    {
        suppressHostedTimerEffectObjects = suppress;
        suppressHostedSendDatagramEffectObjects = suppress;
        pendingHostedSendDatagramUpdateIndex = 0;
        pendingHostedSendDatagramUpdates?.Clear();
        if (!suppress)
        {
            pendingHostedTimerUpdates?.Clear();
        }
    }

    internal bool TryTakePendingHostedSendDatagramUpdate(out QuicConnectionSendDatagramUpdate update)
    {
        if (pendingHostedSendDatagramUpdates is not { } updates
            || (uint)pendingHostedSendDatagramUpdateIndex >= (uint)updates.Count)
        {
            update = default;
            return false;
        }

        update = updates[pendingHostedSendDatagramUpdateIndex++];
        return true;
    }

    internal void ApplyPendingHostedTimerUpdates(
        QuicConnectionHandle handle,
        QuicConnectionRuntimeDeadlineScheduler scheduler)
    {
        if (pendingHostedTimerUpdates is not { Count: > 0 } updates)
        {
            return;
        }

        for (int index = 0; index < updates.Count; index++)
        {
            scheduler.Apply(handle, this, updates[index]);
        }

        updates.Clear();
    }

    internal bool TryMarkPeerAddressValidatedByAddressValidationToken(long nowTicks)
    {
        bool wasValidated = (transportFlags & QuicConnectionTransportState.PeerAddressValidated) != 0;
        transportFlags |= QuicConnectionTransportState.PeerAddressValidated;

        bool stateChanged = !wasValidated;
        if (activePath is not null)
        {
            stateChanged |= TryMarkActivePathValidated(nowTicks);
        }

        return stateChanged;
    }

    private byte[] CreateAddressValidationToken(QuicConnectionPathIdentity pathIdentity)
    {
        return addressValidationTokenProtector.IssueNewToken(pathIdentity.RemoteAddress);
    }
}
