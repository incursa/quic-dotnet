// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal enum QuicServerZeroRttAdmissionFailure
{
    None = 0,
    PskNotValidated = 1,
    TransportParametersRejected = 2,
    ReplayOrUnknownTicket = 3,
}

internal readonly record struct QuicServerZeroRttAdmissionDecision(
    bool CanAdmit,
    QuicServerZeroRttAdmissionFailure Failure,
    QuicZeroRttTransportParameterAcceptanceFailure TransportParameterFailure,
    string? ParameterName)
{
    internal static QuicServerZeroRttAdmissionDecision Accept { get; } =
        new(true, QuicServerZeroRttAdmissionFailure.None, QuicZeroRttTransportParameterAcceptanceFailure.None, null);

    internal static QuicServerZeroRttAdmissionDecision Reject(
        QuicServerZeroRttAdmissionFailure failure,
        QuicZeroRttTransportParameterAcceptanceFailure transportParameterFailure = QuicZeroRttTransportParameterAcceptanceFailure.None,
        string? parameterName = null)
        => new(false, failure, transportParameterFailure, parameterName);
}

internal sealed class QuicServerZeroRttAdmissionGate
{
    private readonly QuicServerResumptionTicketStore ticketStore;

    internal QuicServerZeroRttAdmissionGate(QuicServerResumptionTicketStore ticketStore)
    {
        this.ticketStore = ticketStore ?? throw new ArgumentNullException(nameof(ticketStore));
    }

    internal QuicServerZeroRttAdmissionDecision TryAdmit(
        bool pskBinderValidated,
        ReadOnlySpan<byte> ticketIdentity,
        QuicTransportParameters? rememberedTransportParameters,
        QuicTransportParameters? currentServerTransportParameters,
        long nowTicks,
        out QuicServerResumptionTicketRecord ticket)
    {
        ticket = null!;
        // CONTEXT: Admission is ordered binder validation -> transport-parameter acceptance -> live ticket
        // consumption so replay/unknown-ticket failures stay distinct from remembered-state mismatches.
        // SEE: code:src/Incursa.Quic/QuicZeroRttTransportParameterPolicy.cs#EvaluateServerZeroRttAcceptance
        // SEE: code:src/Incursa.Quic/QuicServerResumptionTicketStore.cs#TryConsumeLiveTicketForEarlyData
        if (!pskBinderValidated)
        {
            return QuicServerZeroRttAdmissionDecision.Reject(QuicServerZeroRttAdmissionFailure.PskNotValidated);
        }

        QuicZeroRttTransportParameterAcceptanceDecision transportDecision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                rememberedTransportParameters,
                currentServerTransportParameters);
        if (!transportDecision.CanAccept)
        {
            return QuicServerZeroRttAdmissionDecision.Reject(
                QuicServerZeroRttAdmissionFailure.TransportParametersRejected,
                transportDecision.Failure,
                transportDecision.ParameterName);
        }

        return ticketStore.TryConsumeLiveTicketForEarlyData(ticketIdentity, nowTicks, out ticket)
            ? QuicServerZeroRttAdmissionDecision.Accept
            : QuicServerZeroRttAdmissionDecision.Reject(QuicServerZeroRttAdmissionFailure.ReplayOrUnknownTicket);
    }
}
