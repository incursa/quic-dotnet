using System;
using Xunit.Sdk;

namespace Incursa.Quic.Tests;

[TraitDiscoverer("Incursa.Quic.Tests.CoverageTypeTraitDiscoverer", "Incursa.Quic.Tests")]
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class CoverageTypeAttribute : Attribute, ITraitAttribute
{
    public CoverageTypeAttribute(RequirementCoverageType coverageType)
    {
        CoverageType = coverageType;
    }

    /// <summary>
    /// Gets the coverage type.
    /// </summary>
    public RequirementCoverageType CoverageType { get; }
}
