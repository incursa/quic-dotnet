```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host] : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                    | Mean       | Error | Allocated |
|-------------------------- |-----------:|------:|----------:|
| ParseAckFrame             | 1,244.0 μs |    NA |     264 B |
| FormatAckFrame            |   286.6 μs |    NA |         - |
| ParseAckEcnFrame          | 1,355.5 μs |    NA |     264 B |
| FormatAckEcnFrame         |   257.2 μs |    NA |         - |
| ParseCryptoFrame          |   942.0 μs |    NA |         - |
| FormatCryptoFrame         |   621.0 μs |    NA |         - |
| FormatLargeStreamFrame    |   468.1 μs |    NA |         - |
| FormatStreamFrame         |   458.6 μs |    NA |         - |
| ParseStreamsBlockedFrame  |   858.7 μs |    NA |         - |
| FormatStreamsBlockedFrame |   271.3 μs |    NA |         - |
