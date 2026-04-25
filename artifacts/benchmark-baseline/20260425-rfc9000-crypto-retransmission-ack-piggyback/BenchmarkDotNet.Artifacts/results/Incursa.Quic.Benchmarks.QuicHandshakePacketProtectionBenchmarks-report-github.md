```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host]   : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  ShortRun : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=ShortRun  IterationCount=3  LaunchCount=1
WarmupCount=3

```
| Method                                          | Mean       | Error      | StdDev   | Gen0   | Gen1   | Allocated |
|------------------------------------------------ |-----------:|-----------:|---------:|-------:|-------:|----------:|
| ProtectHandshakePacket                          |   899.3 ns |   556.5 ns | 30.51 ns | 0.0105 |      - |      88 B |
| OpenHandshakePacket                             |   908.5 ns |   187.8 ns | 10.29 ns | 0.0105 |      - |      88 B |
| BuildInitialCryptoPacket                        | 1,861.7 ns | 1,394.8 ns | 76.46 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoPacketWithAck                 | 1,804.8 ns |   721.1 ns | 39.53 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoRetransmissionPacketWithAck   | 1,872.8 ns |   681.1 ns | 37.33 ns | 0.3109 | 0.0019 |    2616 B |
| BuildHandshakeCryptoPacket                      | 1,311.4 ns |   706.2 ns | 38.71 ns | 0.0553 |      - |     464 B |
| BuildHandshakeCryptoPacketWithAck               | 1,272.2 ns | 1,210.9 ns | 66.37 ns | 0.0572 |      - |     480 B |
| BuildHandshakeCryptoRetransmissionPacketWithAck | 1,224.4 ns |   585.4 ns | 32.09 ns | 0.0648 |      - |     544 B |
