// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Linq;
using Xunit.Abstractions;
using Xunit.Sdk;

namespace Incursa.Quic.Tests;

public sealed class CoverageTypeTraitDiscoverer : ITraitDiscoverer
{
    public IEnumerable<KeyValuePair<string, string>> GetTraits(IAttributeInfo traitAttribute)
    {
        object? coverageType = traitAttribute.GetConstructorArguments().FirstOrDefault();

        if (coverageType is not RequirementCoverageType typedCoverageType)
        {
            return [];
        }

        return [new("CoverageType", typedCoverageType.ToString())];
    }
}
