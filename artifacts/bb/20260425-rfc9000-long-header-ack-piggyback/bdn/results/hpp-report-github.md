```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1
WarmupCount=3

```
| Method                            | Mean       | Error      | StdDev    | Gen0   | Gen1   | Allocated |
|---------------------------------- |-----------:|-----------:|----------:|-------:|-------:|----------:|
| ProtectHandshakePacket            |   923.1 ns |   851.8 ns |  46.69 ns | 0.0105 |      - |      88 B |
| OpenHandshakePacket               |   945.5 ns |   713.5 ns |  39.11 ns | 0.0105 |      - |      88 B |
| BuildInitialCryptoPacket          | 1,699.2 ns |   919.3 ns |  50.39 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoPacketWithAck   | 1,883.4 ns | 2,612.9 ns | 143.22 ns | 0.2995 | 0.0019 |    2520 B |
| BuildHandshakeCryptoPacket        | 1,255.3 ns | 1,179.1 ns |  64.63 ns | 0.0553 |      - |     464 B |
| BuildHandshakeCryptoPacketWithAck | 1,348.4 ns | 1,365.3 ns |  74.84 ns | 0.0572 |      - |     480 B |
