// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal static class QuicTransportParameterCommitHelper
{
    internal static QuicConnectionTransportParametersCommittedEvent CreateLocalTransportParametersCommittedEvent(
        long observedAtTicks,
        QuicTransportParameters localTransportParameters)
    {
        ArgumentNullException.ThrowIfNull(localTransportParameters);

        return new QuicConnectionTransportParametersCommittedEvent(
            ObservedAtTicks: observedAtTicks,
            TransportFlags: QuicConnectionTransportState.None,
            LocalMaxIdleTimeoutMicros: QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(
                localTransportParameters.MaxIdleTimeout));
    }

    internal static QuicConnectionTransportParametersCommittedEvent CreatePeerTransportParametersCommittedEvent(
        long observedAtTicks,
        QuicTransportParameters peerTransportParameters)
    {
        ArgumentNullException.ThrowIfNull(peerTransportParameters);

        QuicConnectionTransportState transportFlags = QuicConnectionTransportState.PeerTransportParametersCommitted;
        if (peerTransportParameters.DisableActiveMigration)
        {
            transportFlags |= QuicConnectionTransportState.DisableActiveMigration;
        }

        return new QuicConnectionTransportParametersCommittedEvent(
            ObservedAtTicks: observedAtTicks,
            TransportFlags: transportFlags,
            PeerMaxIdleTimeoutMicros: QuicTransportParameterTimeUnits.MaxIdleTimeoutMillisecondsToRuntimeMicros(
                peerTransportParameters.MaxIdleTimeout));
    }

    internal static int GetPositiveIncrement(ulong originalValue, ulong updatedValue)
    {
        if (updatedValue <= originalValue)
        {
            return 0;
        }

        ulong increment = updatedValue - originalValue;
        return increment > int.MaxValue ? int.MaxValue : (int)increment;
    }
}
