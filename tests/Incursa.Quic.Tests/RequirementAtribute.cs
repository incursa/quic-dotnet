using System;
using Xunit.Sdk;

namespace Incursa.Quic.Tests;

[TraitDiscoverer("Incursa.Quic.Tests.RequirementTraitDiscoverer", "Incursa.Quic.Tests")]
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class RequirementAttribute : Attribute, ITraitAttribute
{
    public RequirementAttribute(string requirement)
    {
        Requirement = requirement;
    }

    /// <summary>
    /// Gets the requirement.
    /// </summary>
    public string Requirement { get; }
}
