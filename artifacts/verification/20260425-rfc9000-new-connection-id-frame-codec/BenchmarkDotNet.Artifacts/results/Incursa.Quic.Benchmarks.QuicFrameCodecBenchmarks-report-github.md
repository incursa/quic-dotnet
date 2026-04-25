```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host] : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                     | Mean       | Error | Allocated |
|--------------------------- |-----------:|------:|----------:|
| ParseAckFrame              |   979.3 μs |    NA |     264 B |
| FormatAckFrame             |   227.9 μs |    NA |         - |
| ParseAckEcnFrame           | 1,183.3 μs |    NA |     264 B |
| FormatAckEcnFrame          |   230.8 μs |    NA |         - |
| ParseCryptoFrame           |   974.5 μs |    NA |         - |
| FormatCryptoFrame          |   573.8 μs |    NA |         - |
| FormatLargeStreamFrame     |   460.8 μs |    NA |         - |
| FormatStreamFrame          |   439.7 μs |    NA |         - |
| ParseNewConnectionIdFrame  |   841.1 μs |    NA |         - |
| FormatNewConnectionIdFrame |   297.7 μs |    NA |         - |
| ParseStreamsBlockedFrame   |   773.9 μs |    NA |         - |
| FormatStreamsBlockedFrame  |   252.4 μs |    NA |         - |
