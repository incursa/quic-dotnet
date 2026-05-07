```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.202
  [Host] : .NET 10.0.6 (10.0.6, 10.0.626.17701), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.6 (10.0.6, 10.0.626.17701), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                                                     | Mean     | Error | Allocated |
|----------------------------------------------------------- |---------:|------:|----------:|
| GenerateStatelessResetToken                                | 581.3 μs |    NA |     672 B |
| GenerateStatelessResetTokenWithAlternateConnectionIdLength | 418.8 μs |    NA |     680 B |
| FormatStatelessResetDatagram                               | 275.8 μs |    NA |         - |
| FormatLargerStatelessResetDatagram                         | 277.3 μs |    NA |         - |
| FormatStatelessResetDatagramWithRetainedVersionProfile     | 379.0 μs |    NA |         - |
| MatchStatelessResetTokenHit                                | 571.0 μs |    NA |         - |
| MatchStatelessResetTokenMiss                               | 503.5 μs |    NA |         - |
| MatchStatelessResetTokenAgainstLargerFlattenedTokenSet     | 527.2 μs |    NA |         - |
