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
| ProtectHandshakePacket                          |   783.6 ns |   418.1 ns | 22.92 ns | 0.0105 |      - |      88 B |
| OpenHandshakePacket                             |   782.9 ns |   300.3 ns | 16.46 ns | 0.0105 |      - |      88 B |
| BuildInitialCryptoPacket                        | 1,480.9 ns |   618.9 ns | 33.92 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoPacketWithAck                 | 1,575.2 ns | 1,041.4 ns | 57.09 ns | 0.2995 | 0.0019 |    2520 B |
| BuildInitialCryptoRetransmissionPacketWithAck   | 1,569.4 ns |   537.5 ns | 29.46 ns | 0.3109 | 0.0019 |    2616 B |
| BuildRetrySelectedInitialReplayPacketWithAck    | 1,545.6 ns |   286.5 ns | 15.70 ns | 0.3071 | 0.0019 |    2584 B |
| BuildHandshakeCryptoPacket                      | 1,033.2 ns |   188.9 ns | 10.35 ns | 0.0553 |      - |     464 B |
| BuildHandshakeCryptoPacketWithAck               | 1,022.4 ns |   115.5 ns |  6.33 ns | 0.0572 |      - |     480 B |
| BuildHandshakeCryptoRetransmissionPacketWithAck | 1,083.8 ns |   357.8 ns | 19.61 ns | 0.0648 |      - |     544 B |
