```

BenchmarkDotNet v0.15.8, Windows 11 (10.0.26200.8246/25H2/2025Update/HudsonValley2)
AMD Ryzen 9 3950X 3.50GHz, 1 CPU, 32 logical and 16 physical cores
.NET SDK 10.0.203
  [Host] : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3
  Dry    : .NET 10.0.7 (10.0.7, 10.0.726.21808), X64 RyuJIT x86-64-v3

Job=Dry  IterationCount=1  LaunchCount=1
RunStrategy=ColdStart  UnrollFactor=1  WarmupCount=1

```
| Method                                                 | Mean       | Error | Allocated |
|------------------------------------------------------- |-----------:|------:|----------:|
| RecordCurrentKeyPhaseAcknowledgmentAndArmCooldown      |   325.6 μs |    NA |         - |
| CheckRepeatedLocalKeyUpdateEligibilityAfterCooldown    |   353.1 μs |    NA |         - |
| EvaluateRepeatedAeadLimitUpdateDecisionAfterCooldown   |   814.4 μs |    NA |         - |
| DiscardRepeatedOldPhaseOnePacketProtectionAndSendState | 9,725.5 μs |    NA |     544 B |
| DiscardRepeatedOldPhaseTwoPacketProtectionAndSendState | 8,355.6 μs |    NA |     544 B |
