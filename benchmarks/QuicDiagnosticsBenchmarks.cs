using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the disabled diagnostics branch used by transport hot paths.
/// </summary>
[MemoryDiagnoser]
public class QuicDiagnosticsBenchmarks
{
    private static readonly QuicConnectionPathIdentity PathIdentity = new(
        RemoteAddress: "203.0.113.20",
        LocalAddress: "198.51.100.4",
        RemotePort: 443,
        LocalPort: 61235);

    private readonly IQuicDiagnosticsSink disabledSink = QuicDiagnostics.ResolveConnectionSink();
    private readonly CountingDiagnosticsSink enabledSink = new();

    [Benchmark]
    public bool ResolveDisabledConnectionSink()
    {
        return ReferenceEquals(QuicDiagnostics.ResolveConnectionSink(), QuicNullDiagnosticsSink.Instance);
    }

    [Benchmark]
    public void DisabledNullSinkEmitDefault()
    {
        disabledSink.Emit(default);
    }

    [Benchmark]
    public int DisabledHotPathGuardSkipsEventConstruction()
    {
        if (disabledSink.IsEnabled)
        {
            disabledSink.Emit(QuicDiagnostics.InitialPacketReceived(PathIdentity));
            return 1;
        }

        return 0;
    }

    [Benchmark]
    public int EnabledHotPathConstructsTypedEvent()
    {
        if (enabledSink.IsEnabled)
        {
            enabledSink.Emit(QuicDiagnostics.InitialPacketReceived(PathIdentity));
            return enabledSink.EmittedEvents;
        }

        return 0;
    }

    private sealed class CountingDiagnosticsSink : IQuicDiagnosticsSink
    {
        public int EmittedEvents { get; private set; }

        public bool IsEnabled => true;

        public void Emit(QuicDiagnosticEvent diagnosticEvent)
        {
            if (diagnosticEvent.Kind != QuicDiagnosticKind.Unknown)
            {
                EmittedEvents++;
            }
        }
    }
}
