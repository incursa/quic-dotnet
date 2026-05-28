// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;

namespace Incursa.Quic;

internal sealed partial class QuicConnectionRuntime
{
    private bool ApplyTlsStateUpdates(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        long observedAtTicks,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects)
    {
        return ApplyTlsStateUpdates(
            updates,
            observedAtTicks,
            nowTicks,
            ref effects,
            false,
            out _);
    }

    private bool ApplyTlsStateUpdates(
        IReadOnlyList<QuicTlsStateUpdate> updates,
        long observedAtTicks,
        long nowTicks,
        ref List<QuicConnectionEffect>? effects,
        bool stopOnFatalAlert,
        out bool sawFatalAlert)
    {
        bool stateChanged = false;
        sawFatalAlert = false;

        for (int i = 0; i < updates.Count; i++)
        {
            QuicTlsStateUpdate update = updates[i];
            stateChanged |= HandleTlsStateUpdated(
                new QuicConnectionTlsStateUpdatedEvent(observedAtTicks, update),
                nowTicks,
                ref effects);

            if (stopOnFatalAlert && update.Kind == QuicTlsUpdateKind.FatalAlert)
            {
                sawFatalAlert = true;
                break;
            }
        }

        return stateChanged;
    }
}
