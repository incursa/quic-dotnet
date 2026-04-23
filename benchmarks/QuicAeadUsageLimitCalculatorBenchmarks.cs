using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the RFC 9001 Appendix B AEAD usage-limit calculator.
/// </summary>
[MemoryDiagnoser]
public class QuicAeadUsageLimitCalculatorBenchmarks
{
    /// <summary>
    /// Measures the strict packet-size GCM limit path.
    /// </summary>
    [Benchmark]
    public double GetAes128GcmStrictUsageLimits()
    {
        return QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Gcm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits)
            ? limits.ConfidentialityLimitPackets + limits.IntegrityLimitPackets
            : -1d;
    }

    /// <summary>
    /// Measures the large-packet GCM confidentiality path with unrestricted integrity accounting.
    /// </summary>
    [Benchmark]
    public double GetAes256GcmLargePacketUsageLimits()
    {
        return QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes256Gcm,
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out QuicAeadUsageLimits limits)
            ? limits.ConfidentialityLimitPackets + limits.IntegrityLimitPackets
            : -1d;
    }

    /// <summary>
    /// Measures the strict packet-size CCM limit path.
    /// </summary>
    [Benchmark]
    public double GetAes128CcmStrictUsageLimits()
    {
        return QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            out QuicAeadUsageLimits limits)
            ? limits.ConfidentialityLimitPackets + limits.IntegrityLimitPackets
            : -1d;
    }

    /// <summary>
    /// Measures rejection of unsupported AEAD/profile combinations.
    /// </summary>
    [Benchmark]
    public int RejectUnsupportedUsageLimitProfile()
    {
        return QuicAeadUsageLimitCalculator.TryGetUsageLimits(
            QuicAeadAlgorithm.Aes128Ccm,
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes,
            QuicAeadPacketSizeProfile.Unrestricted,
            out _)
            ? 1
            : 0;
    }
}
