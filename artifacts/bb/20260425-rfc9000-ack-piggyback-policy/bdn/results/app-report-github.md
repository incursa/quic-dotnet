```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1  
WarmupCount=3  

```
| Method                                        | Mean     | Error    | StdDev   | Gen0   | Allocated |
|---------------------------------------------- |---------:|---------:|---------:|-------:|----------:|
| PendingAckShouldPiggyback                     | 32.96 ns | 28.26 ns | 1.549 ns | 0.0086 |      72 B |
| AlreadyPiggybackedAckSuppressesAckOnlyTrigger | 33.10 ns | 35.88 ns | 1.966 ns | 0.0086 |      72 B |
