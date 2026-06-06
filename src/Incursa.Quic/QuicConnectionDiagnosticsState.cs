// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;

namespace Incursa.Quic;

// CONTEXT: The state is a readonly struct so the runtime can cache sink resolution and the
// enabled flag once per connection, avoiding repeated null/IsEnabled checks on the hot path.
// SEE: QuicDiagnostics.ResolveConnectionSink
internal readonly struct QuicConnectionDiagnosticsState
{
    internal QuicConnectionDiagnosticsState(IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        Sink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSink);
        IsEnabled = Sink.IsEnabled;
    }

    internal IQuicDiagnosticsSink Sink { get; }

    internal bool IsEnabled { get; }

    internal void EmitDiagnostic(ref QuicConnectionEffectAccumulator effects, QuicDiagnosticEvent diagnosticEvent)
    {
        if (!IsEnabled)
        {
            return;
        }

        Sink.Emit(diagnosticEvent);
        effects.Add(new QuicConnectionEmitDiagnosticEffect(diagnosticEvent));
    }
}
