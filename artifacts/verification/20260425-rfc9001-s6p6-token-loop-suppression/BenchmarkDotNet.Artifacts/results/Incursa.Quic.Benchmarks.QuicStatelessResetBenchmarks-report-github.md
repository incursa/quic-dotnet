```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host] : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                                                     | Mean       | Error | Allocated |
|----------------------------------------------------------- |-----------:|------:|----------:|
| GenerateStatelessResetToken                                |   389.7 μs |    NA |     672 B |
| GenerateStatelessResetTokenWithAlternateConnectionIdLength |   436.9 μs |    NA |     680 B |
| FormatStatelessResetDatagram                               |   269.9 μs |    NA |         - |
| FormatLargerStatelessResetDatagram                         |   281.0 μs |    NA |         - |
| FormatStatelessResetDatagramWithRetainedVersionProfile     |   364.9 μs |    NA |         - |
| MatchStatelessResetTokenHit                                |   780.0 μs |    NA |         - |
| MatchStatelessResetTokenMiss                               |   529.1 μs |    NA |         - |
| MatchStatelessResetTokenAgainstLargerFlattenedTokenSet     |   516.2 μs |    NA |         - |
| CreateRetainedRouteStatelessResetDatagramHit               | 4,500.4 μs |    NA |     336 B |
| CreateRetainedRouteStatelessResetDatagramMiss              | 1,551.9 μs |    NA |         - |
| SuppressRetainedRouteKnownStatelessResetResponse           | 2,430.5 μs |    NA |         - |
