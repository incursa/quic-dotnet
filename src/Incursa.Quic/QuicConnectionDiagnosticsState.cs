using System.Collections.Generic;

namespace Incursa.Quic;

internal readonly struct QuicConnectionDiagnosticsState
{
    internal QuicConnectionDiagnosticsState(IQuicDiagnosticsSink? diagnosticsSink = null)
    {
        Sink = QuicDiagnostics.ResolveConnectionSink(diagnosticsSink);
        IsEnabled = Sink.IsEnabled;
    }

    internal IQuicDiagnosticsSink Sink { get; }

    internal bool IsEnabled { get; }

    internal void EmitDiagnostic(ref List<QuicConnectionEffect>? effects, QuicDiagnosticEvent diagnosticEvent)
    {
        if (!IsEnabled)
        {
            return;
        }

        Sink.Emit(diagnosticEvent);
        (effects ??= []).Add(new QuicConnectionEmitDiagnosticEffect(diagnosticEvent));
    }
}
