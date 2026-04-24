```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method                           | Mean       | Error      | StdDev    | Median     | Gen0   | Allocated |
|--------------------------------- |-----------:|-----------:|----------:|-----------:|-------:|----------:|
| ComputeInitialCongestionWindow   |  0.0889 ns |  1.0698 ns | 0.0586 ns |  0.1005 ns |      - |         - |
| NormalizeRecoveryMaxDatagramSize |  0.0000 ns |  0.0000 ns | 0.0000 ns |  0.0000 ns |      - |         - |
| ComputeBytesInFlightPayloadBytes |  0.0760 ns |  0.3299 ns | 0.0181 ns |  0.0707 ns |      - |         - |
| GrowInSlowStart                  |  0.0496 ns |  1.0797 ns | 0.0592 ns |  0.0338 ns |      - |         - |
| EnterRecoveryOnLoss              |  0.6118 ns |  1.3552 ns | 0.0743 ns |  0.6403 ns |      - |         - |
| ProcessValidatedEcn              |  9.4619 ns | 10.0161 ns | 0.5490 ns |  9.3785 ns | 0.0057 |      48 B |
| DetectPersistentCongestion       | 10.9332 ns |  4.0928 ns | 0.2243 ns | 11.0178 ns |      - |         - |
