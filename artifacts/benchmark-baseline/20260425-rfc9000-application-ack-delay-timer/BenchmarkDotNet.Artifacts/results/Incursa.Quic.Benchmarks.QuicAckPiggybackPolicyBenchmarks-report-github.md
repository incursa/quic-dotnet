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
| PendingAckShouldPiggyback                     | 28.76 ns | 14.90 ns | 0.817 ns | 0.0086 |      72 B |
| AlreadyPiggybackedAckSuppressesAckOnlyTrigger | 28.23 ns | 18.37 ns | 1.007 ns | 0.0086 |      72 B |
| SingleAckWaitsBeforeMaxAckDelay               | 28.13 ns | 11.73 ns | 0.643 ns | 0.0086 |      72 B |
| SingleAckSendsAtMaxAckDelay                   | 29.75 ns | 28.03 ns | 1.536 ns | 0.0086 |      72 B |
