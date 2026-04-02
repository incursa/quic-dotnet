namespace Incursa.Quic.Tests;

/// <summary>
/// Describes the kind of evidence a test provides.
/// </summary>
public enum RequirementCoverageType
{
    Positive,
    Negative,
    Edge,
    Fuzz,
    Benchmark
}
