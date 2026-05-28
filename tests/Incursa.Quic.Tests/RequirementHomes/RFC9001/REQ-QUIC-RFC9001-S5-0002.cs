// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0002")]
public sealed class REQ_QUIC_RFC9001_S5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesTlsNegotiatedPacketProtectionMaterialUpdates()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        byte[] aeadKey = CreateSequentialBytes(0x11, 16);
        byte[] aeadIv = CreateSequentialBytes(0x21, 12);
        byte[] headerProtectionKey = CreateSequentialBytes(0x31, 16);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Ccm,
            aeadKey,
            aeadIv,
            headerProtectionKey,
            new QuicAeadUsageLimits(32, 64),
            out QuicTlsPacketProtectionMaterial material));

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: material)),
            nowTicks: 10).StateChanged);

        aeadKey[0] = 0xFF;
        aeadIv[0] = 0xEE;
        headerProtectionKey[0] = 0xDD;

        Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial storedMaterial));
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, storedMaterial.EncryptionLevel);
        Assert.Equal(QuicAeadAlgorithm.Aes128Ccm, storedMaterial.Algorithm);
        Assert.Equal(32d, storedMaterial.UsageLimits.ConfidentialityLimitPackets);
        Assert.Equal(64d, storedMaterial.UsageLimits.IntegrityLimitPackets);
        Assert.Equal(16, storedMaterial.AeadKey.Length);
        Assert.Equal(12, storedMaterial.AeadIv.Length);
        Assert.Equal(16, storedMaterial.HeaderProtectionKey.Length);
        Assert.True(CreateSequentialBytes(0x11, 16).AsSpan().SequenceEqual(storedMaterial.AeadKey));
        Assert.True(CreateSequentialBytes(0x21, 12).AsSpan().SequenceEqual(storedMaterial.AeadIv));
        Assert.True(CreateSequentialBytes(0x31, 16).AsSpan().SequenceEqual(storedMaterial.HeaderProtectionKey));
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);

        QuicConnectionRuntime chacha20Runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            clock,
            selectedCipherSuite: QuicTlsCipherSuite.TlsChacha20Poly1305Sha256);
        byte[] chacha20AeadKey = CreateSequentialBytes(0x41, 32);
        byte[] chacha20AeadIv = CreateSequentialBytes(0x51, 12);
        byte[] chacha20HeaderProtectionKey = CreateSequentialBytes(0x61, 32);

        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Chacha20Poly1305,
            chacha20AeadKey,
            chacha20AeadIv,
            chacha20HeaderProtectionKey,
            new QuicAeadUsageLimits(32, 64),
            out QuicTlsPacketProtectionMaterial chacha20Material));

        Assert.True(chacha20Runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 20,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
                    PacketProtectionMaterial: chacha20Material)),
            nowTicks: 20).StateChanged);

        chacha20AeadKey[0] = 0xFF;
        chacha20AeadIv[0] = 0xEE;
        chacha20HeaderProtectionKey[0] = 0xDD;

        Assert.True(chacha20Runtime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial storedChacha20Material));
        Assert.Equal(QuicTlsEncryptionLevel.OneRtt, storedChacha20Material.EncryptionLevel);
        Assert.Equal(QuicAeadAlgorithm.Chacha20Poly1305, storedChacha20Material.Algorithm);
        Assert.Equal(32d, storedChacha20Material.UsageLimits.ConfidentialityLimitPackets);
        Assert.Equal(64d, storedChacha20Material.UsageLimits.IntegrityLimitPackets);
        Assert.Equal(32, storedChacha20Material.AeadKey.Length);
        Assert.Equal(12, storedChacha20Material.AeadIv.Length);
        Assert.Equal(32, storedChacha20Material.HeaderProtectionKey.Length);
        Assert.True(CreateSequentialBytes(0x41, 32).AsSpan().SequenceEqual(storedChacha20Material.AeadKey));
        Assert.True(CreateSequentialBytes(0x51, 12).AsSpan().SequenceEqual(storedChacha20Material.AeadIv));
        Assert.True(CreateSequentialBytes(0x61, 32).AsSpan().SequenceEqual(storedChacha20Material.HeaderProtectionKey));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryCreate_RejectsUnsupportedAeadAlgorithms()
    {
        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            (QuicAeadAlgorithm)999,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(32, 64),
            out _));

        Assert.False(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Ccm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(double.NaN, 64),
            out _));
    }

    private static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
