```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host] : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                                                          | Mean       | Error | Allocated |
|---------------------------------------------------------------- |-----------:|------:|----------:|
| GenerateStatelessResetToken                                     |   358.3 μs |    NA |     672 B |
| GenerateStatelessResetTokenWithAlternateConnectionIdLength      |   325.3 μs |    NA |     680 B |
| FormatStatelessResetDatagram                                    |   246.2 μs |    NA |         - |
| FormatLargerStatelessResetDatagram                              |   251.3 μs |    NA |         - |
| FormatStatelessResetDatagramWithRetainedVersionProfile          |   330.0 μs |    NA |         - |
| MatchStatelessResetTokenHit                                     |   576.6 μs |    NA |         - |
| MatchStatelessResetTokenMiss                                    |   499.4 μs |    NA |         - |
| MatchStatelessResetTokenAgainstLargerFlattenedTokenSet          |   571.7 μs |    NA |         - |
| CreateRetainedRouteStatelessResetDatagramHit                    | 4,552.7 μs |    NA |     336 B |
| CreateRetainedRouteStatelessResetDatagramMiss                   | 1,890.5 μs |    NA |         - |
| CreateRetainedRouteStatelessResetDatagramWithoutRememberedToken |   999.1 μs |    NA |         - |
| SuppressRetainedRouteKnownStatelessResetResponse                | 2,262.3 μs |    NA |         - |
