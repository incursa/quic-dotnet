using System.Collections.Generic;
using System.Linq;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Incursa.Quic.Tests;

public sealed class RequirementTraitDiscoverer : ITraitDiscoverer
{
    public IEnumerable<KeyValuePair<string, string>> GetTraits(IAttributeInfo traitAttribute)
    {
        string? requirement = traitAttribute.GetConstructorArguments().OfType<string>().FirstOrDefault();

        if (string.IsNullOrWhiteSpace(requirement))
        {
            return [];
        }

        return [new("Requirement", requirement)];
    }
}
