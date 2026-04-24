# RFC9000 S9P6P3 preferred-address fallback evidence

## Verified behavior

- `REQ-QUIC-RFC9000-S9P6P3-0003` now keeps the connection alive when preferred-address validation fails but the original-address candidate is still pending.
- The broader RFC9000 S9 sweep still passes after the fix.

## Commands

```powershell
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9P6P3_0003.ClientMayContinueSendingToTheOriginalServerAddressWhenPreferredAddressValidationFails"
dotnet test tests\Incursa.Quic.Tests\Incursa.Quic.Tests.csproj --no-restore -m:1 --filter "FullyQualifiedName~REQ_QUIC_RFC9000_S9"
.\scripts\benchmarks\Invoke-QuicBaseline.ps1 -Job Dry
```

## Result summary

- Focused regression: passed `1/1`.
- Broader S9 sweep: passed `114/114`.
- Dry benchmark baseline: passed `12/12` benchmark cases across congestion control, RTT estimation, and stream-state suites.

## Preserved benchmark outputs

- `rfc9000-s9p6p3-0003-regression.log`
- `rfc9000-s9-sweep.log`
- `baseline-dry.log`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicCongestionControlBenchmarks-report.html`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicRttEstimatorBenchmarks-report.html`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report.csv`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report-github.md`
- `Incursa.Quic.Benchmarks.QuicConnectionStreamStateBenchmarks-report.html`
