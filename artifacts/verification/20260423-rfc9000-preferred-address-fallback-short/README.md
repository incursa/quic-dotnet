# RFC9000 S9P6P3 preferred-address fallback Short evidence

## Verified behavior

- The repo baseline `Short` run completed after the preferred-address fallback fix.
- The run stayed in the sub-microsecond range on this machine and did not surface any new failures.

## Commands

```powershell
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Short
```

## Result summary

- `QuicCongestionControlBenchmarks`: mostly sub-nanosecond logical results on this machine, with the ECN and persistent-congestion checks in the low tens of nanoseconds.
- `QuicRttEstimatorBenchmarks`: mostly sub-nanosecond logical results on this machine, with the RTT update path in the low single-digit nanoseconds.
- `QuicConnectionStreamStateBenchmarks`: `176.5 ns` to `424.4 ns` with `816 B` to `1392 B` allocated per operation.

## Preserved benchmark outputs

- `baseline-short.log`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report.html`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report.html`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report.html`
