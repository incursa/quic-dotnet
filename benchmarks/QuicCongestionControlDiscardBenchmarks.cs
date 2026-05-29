// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks sender-flow retained-packet discard scans used by key discard and packet-protection cleanup.
/// </summary>
[MemoryDiagnoser]
public class QuicCongestionControlDiscardBenchmarks
{
    private QuicSenderFlowController noMatchController = new();
    private QuicSenderFlowController discardController = new();

    /// <summary>
    /// Gets or sets the number of retained packets per packet number space.
    /// </summary>
    [Params(8, 128, 512)]
    public int RetainedPacketsPerSpace { get; set; }

    /// <summary>
    /// Prepares a retained packet ledger with no zero-RTT packets.
    /// </summary>
    [GlobalSetup(Target = nameof(DiscardMissingZeroRttProtectionLevel))]
    public void SetupNoMatchController()
    {
        noMatchController = CreateController();
    }

    /// <summary>
    /// Prepares a retained packet ledger where half of the one-RTT packets use key phase 0.
    /// </summary>
    [IterationSetup(Target = nameof(DiscardOneRttKeyPhaseFromRetainedPackets))]
    public void SetupDiscardController()
    {
        discardController = CreateController();
    }

    /// <summary>
    /// Measures scanning retained packets when the requested packet-protection level is absent.
    /// </summary>
    [Benchmark]
    public ulong DiscardMissingZeroRttProtectionLevel()
    {
        return noMatchController.TryDiscardPacketProtectionLevel(QuicTlsEncryptionLevel.ZeroRtt)
            ? noMatchController.CongestionControlState.BytesInFlightBytes
            : noMatchController.CongestionControlState.BytesInFlightBytes + 1;
    }

    /// <summary>
    /// Measures discarding retained one-RTT packets protected with an old key phase.
    /// </summary>
    [Benchmark]
    public ulong DiscardOneRttKeyPhaseFromRetainedPackets()
    {
        return discardController.TryDiscardOneRttKeyPhase(keyPhase: 0)
            ? discardController.CongestionControlState.BytesInFlightBytes
            : discardController.CongestionControlState.BytesInFlightBytes + 1;
    }

    private QuicSenderFlowController CreateController()
    {
        QuicSenderFlowController controller = new();
        SeedPacketNumberSpace(controller, QuicPacketNumberSpace.Initial, packetNumberOffset: 0, QuicTlsEncryptionLevel.Initial);
        SeedPacketNumberSpace(controller, QuicPacketNumberSpace.Handshake, packetNumberOffset: 10_000, QuicTlsEncryptionLevel.Handshake);
        SeedPacketNumberSpace(controller, QuicPacketNumberSpace.ApplicationData, packetNumberOffset: 20_000, QuicTlsEncryptionLevel.OneRtt);
        return controller;
    }

    private void SeedPacketNumberSpace(
        QuicSenderFlowController controller,
        QuicPacketNumberSpace packetNumberSpace,
        ulong packetNumberOffset,
        QuicTlsEncryptionLevel packetProtectionLevel)
    {
        for (int index = 0; index < RetainedPacketsPerSpace; index++)
        {
            controller.RecordPacketSent(
                packetNumberSpace,
                packetNumberOffset + (ulong)index,
                sentBytes: 1_200,
                sentAtMicros: packetNumberOffset + (ulong)index,
                ackEliciting: true,
                packetProtectionLevel: packetProtectionLevel,
                oneRttKeyPhase: packetProtectionLevel == QuicTlsEncryptionLevel.OneRtt ? (ulong)(index & 1) : null);
        }
    }
}
