```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1
WarmupCount=3

```
| Method                                          | Mean       | Error      | StdDev    | Gen0   | Gen1   | Allocated |
|------------------------------------------------ |-----------:|-----------:|----------:|-------:|-------:|----------:|
| ProtectHandshakePacket                          |   954.7 ns |   667.0 ns |  36.56 ns | 0.0105 |      - |      88 B |
| OpenHandshakePacket                             |   923.6 ns |   125.5 ns |   6.88 ns | 0.0105 |      - |      88 B |
| BuildInitialCryptoPacket                        | 2,054.6 ns | 3,691.6 ns | 202.35 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoPacketWithAck                 | 1,840.5 ns | 2,799.8 ns | 153.46 ns | 0.2995 | 0.0019 |    2520 B |
| BuildBootstrapInitialReplayPacketWithAck        | 1,820.7 ns | 1,887.5 ns | 103.46 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoRetransmissionPacketWithAck   | 1,902.8 ns | 2,878.0 ns | 157.75 ns | 0.3109 | 0.0019 |    2616 B |
| BuildRetrySelectedInitialReplayPacketWithAck    | 1,852.7 ns | 1,715.3 ns |  94.02 ns | 0.3071 | 0.0019 |    2584 B |
| BuildHandshakeCryptoPacket                      | 1,263.0 ns |   362.8 ns |  19.88 ns | 0.0553 |      - |     464 B |
| BuildHandshakeCryptoPacketWithAck               | 1,262.5 ns | 1,605.0 ns |  87.98 ns | 0.0572 |      - |     480 B |
| BuildHandshakeCryptoRetransmissionPacketWithAck | 1,257.5 ns |   575.2 ns |  31.53 ns | 0.0648 |      - |     544 B |
