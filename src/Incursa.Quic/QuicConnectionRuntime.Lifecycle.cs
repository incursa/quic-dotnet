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

        ReadOnlyMemory<byte> closePayload = FormatConnectionClosePayload(closeMetadata);
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
        List<QuicConnectionEffect> effects = [];
        long? idleDueTicks = phase switch
        {
            QuicConnectionPhase.Establishing or QuicConnectionPhase.Active when idleTimeoutState is not null
                => GetAbsoluteTicks(idleTimeoutState.IdleTimeoutDeadlineMicros),
            _ => null,
        };

        long? pathValidationDueTicks = GetEarliestPathValidationDueTicks();
        long? recoveryDueTicks = GetEarliestRecoveryDueTicks();
        long? applicationSendDelayDueTicks = pendingApplicationSendRequests.Count > 0
            ? pendingApplicationSendDelayDueTicks
            : null;

        long? closeDueTicks = phase == QuicConnectionPhase.Closing ? terminalEndTicks : null;
        long? drainDueTicks = phase == QuicConnectionPhase.Draining ? terminalEndTicks : null;

        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.IdleTimeout, idleDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.CloseLifetime, closeDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.DrainLifetime, drainDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.PathValidation, pathValidationDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.Recovery, recoveryDueTicks));
        effects.AddRange(SetTimerDeadline(QuicConnectionTimerKind.ApplicationSendDelay, applicationSendDelayDueTicks));
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
