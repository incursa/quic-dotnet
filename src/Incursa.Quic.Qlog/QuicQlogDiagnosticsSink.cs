using Incursa.Qlog;
using Incursa.Qlog.Quic;

namespace Incursa.Quic.Qlog;

internal sealed class QuicQlogDiagnosticsSink : IQuicDiagnosticsSink
{
    private readonly bool isServer;
    private double nextEventTime;

    public QuicQlogDiagnosticsSink(bool isServer, QlogTrace? trace = null)
    {
        this.isServer = isServer;
        Trace = trace ?? new QlogTrace();
        if (Trace.VantagePoint is null)
        {
            Trace.VantagePoint = new QlogVantagePoint
            {
                Type = isServer ? QlogKnownValues.ServerVantagePoint : QlogKnownValues.ClientVantagePoint,
            };
        }

        QlogQuicEvents.RegisterDraftSchema(Trace);
        nextEventTime = Trace.Events.Count == 0
            ? 0
            : Trace.Events.Max(static existingEvent => existingEvent.Time) + 1;
    }

    public QlogTrace Trace { get; }

    public bool IsEnabled => true;

    public void Emit(QuicDiagnosticEvent diagnosticEvent)
    {
        if (QuicQlogDiagnosticsMapper.TryMap(diagnosticEvent, nextEventTime, isServer, out QlogEvent? mappedEvent) &&
            mappedEvent is not null)
        {
            Trace.Events.Add(mappedEvent);
            nextEventTime += 1;
        }
    }
}
