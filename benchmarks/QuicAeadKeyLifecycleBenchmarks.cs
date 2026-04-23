using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the lightweight AEAD key-use lifecycle that counts protected/opened packets
/// and stops key use once the configured usage limits are reached.
/// </summary>
[MemoryDiagnoser]
public class QuicAeadKeyLifecycleBenchmarks
{
    private QuicAeadKeyLifecycle activeLifecycle = default!;

    [IterationSetup]
    public void IterationSetup()
    {
        activeLifecycle = CreateActiveLifecycle(confidentialityLimit: 1_000_000_000, integrityLimit: 1_000_000_000);
    }

    /// <summary>
    /// Measures recording one encrypted packet against an available key set.
    /// </summary>
    [Benchmark]
    public int CountProtectedPacketForAvailableKeySet()
    {
        return activeLifecycle.TryUseForProtection()
            ? 1
            : -1;
    }

    /// <summary>
    /// Measures the transition that records the limit-reaching packet and discards that key set.
    /// </summary>
    [Benchmark]
    public int RejectFurtherProtectionAtConfidentialityLimit()
    {
        QuicAeadKeyLifecycle keyLifecycle = CreateActiveLifecycle(confidentialityLimit: 2, integrityLimit: 1_000_000);
        return keyLifecycle.TryUseForProtection()
            && keyLifecycle.TryUseForProtection()
            && !keyLifecycle.TryUseForProtection()
            && keyLifecycle.IsDiscarded
            ? 2
            : -1;
    }

    private static QuicAeadKeyLifecycle CreateActiveLifecycle(int confidentialityLimit, int integrityLimit)
    {
        QuicAeadKeyLifecycle keyLifecycle = new(new QuicAeadUsageLimits(confidentialityLimit, integrityLimit));
        if (!keyLifecycle.TryActivate())
        {
            throw new InvalidOperationException("Failed to activate the AEAD key lifecycle state.");
        }

        return keyLifecycle;
    }
}
