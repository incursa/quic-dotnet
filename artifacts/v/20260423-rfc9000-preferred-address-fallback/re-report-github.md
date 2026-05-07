```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method                                 | Mean      | Error     | StdDev    | Allocated |
|--------------------------------------- |----------:|----------:|----------:|----------:|
| ProcessInitialRttSample                | 0.2367 ns | 0.2340 ns | 0.0128 ns |         - |
| ProcessAckDelayAdjustedSample          | 1.6661 ns | 1.0898 ns | 0.0597 ns |         - |
| RefreshMinRttAfterPersistentCongestion | 0.0000 ns | 0.0000 ns | 0.0000 ns |         - |
| ProcessPersistentRttUpdate             | 3.3673 ns | 2.4438 ns | 0.1340 ns |         - |
