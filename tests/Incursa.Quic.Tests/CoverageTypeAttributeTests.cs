using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Xunit;
using Xunit.Abstractions;

namespace Incursa.Quic.Tests;

public sealed class CoverageTypeAttributeTests
{
    [Fact]
    public void AttributeUsageAllowsMethodAndClassTargetsWithMultipleInstances()
    {
        AttributeUsageAttribute? usage = typeof(CoverageTypeAttribute)
            .GetCustomAttribute<AttributeUsageAttribute>();

        Assert.NotNull(usage);
        Assert.Equal(AttributeTargets.Class | AttributeTargets.Method, usage!.ValidOn);
        Assert.True(usage.AllowMultiple);
    }

    [Fact]
    public void ConstructorStoresTheCoverageType()
    {
        CoverageTypeAttribute attribute = new(RequirementCoverageType.Benchmark);

        Assert.Equal(RequirementCoverageType.Benchmark, attribute.CoverageType);
    }

    [Fact]
    public void MultipleAttributesCanBeAppliedToOneMethod()
    {
        CoverageTypeAttribute[] attributes = typeof(CoverageTypeAttributeTests)
            .GetMethod(nameof(MethodWithMultipleCoverageTypes), BindingFlags.NonPublic | BindingFlags.Static)!
            .GetCustomAttributes<CoverageTypeAttribute>()
            .ToArray();

        Assert.Equal(2, attributes.Length);
        Assert.Equal(RequirementCoverageType.Positive, attributes[0].CoverageType);
        Assert.Equal(RequirementCoverageType.Negative, attributes[1].CoverageType);
    }

    [Fact]
    public void TraitDiscovererMapsTheCoverageTypeToATrait()
    {
        CoverageTypeTraitDiscoverer discoverer = new();
        KeyValuePair<string, string>[] traits = discoverer
            .GetTraits(new AttributeInfoStub(RequirementCoverageType.Fuzz))
            .ToArray();

        Assert.Single(traits);
        Assert.Equal("CoverageType", traits[0].Key);
        Assert.Equal("Fuzz", traits[0].Value);
    }

    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    private static void MethodWithMultipleCoverageTypes()
    {
    }

    private sealed class AttributeInfoStub : LongLivedMarshalByRefObject, IAttributeInfo
    {
        private readonly object[] constructorArguments;

        public AttributeInfoStub(params object[] constructorArguments)
        {
            this.constructorArguments = constructorArguments;
        }

        public IEnumerable<object> GetConstructorArguments() => constructorArguments;

        public IEnumerable<IAttributeInfo> GetCustomAttributes(string attributeName) => [];

        public T GetNamedArgument<T>(string name) => default!;
    }
}
