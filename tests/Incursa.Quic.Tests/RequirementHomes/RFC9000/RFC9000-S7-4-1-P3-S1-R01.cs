// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-4-1-P3-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void KnownTransportParameterDefinitionsSpecifyZeroRttStoragePolicy()
    {
        Assert.NotEmpty(QuicZeroRttTransportParameterPolicy.KnownDefinitions);
        Assert.Contains(
            QuicZeroRttTransportParameterPolicy.KnownDefinitions,
            definition => definition.MemoryRequirement == QuicZeroRttTransportParameterMemoryRequirement.Mandatory);
        Assert.Contains(
            QuicZeroRttTransportParameterPolicy.KnownDefinitions,
            definition => definition.MemoryRequirement == QuicZeroRttTransportParameterMemoryRequirement.Optional);
        Assert.Contains(
            QuicZeroRttTransportParameterPolicy.KnownDefinitions,
            definition => definition.MemoryRequirement == QuicZeroRttTransportParameterMemoryRequirement.Prohibited);

        foreach (QuicZeroRttTransportParameterDefinition definition in QuicZeroRttTransportParameterPolicy.KnownDefinitions)
        {
            Assert.False(string.IsNullOrWhiteSpace(definition.Name));
            Assert.True(QuicZeroRttTransportParameterPolicy.TryGetKnownDefinition(
                definition.Id,
                out QuicZeroRttTransportParameterDefinition resolved));
            Assert.Equal(definition, resolved);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void KnownTransportParameterDefinitionsFuzz_RoundTripStoragePolicyById()
    {
        foreach (QuicZeroRttTransportParameterDefinition definition in QuicZeroRttTransportParameterPolicy.KnownDefinitions)
        {
            Assert.True(QuicZeroRttTransportParameterPolicy.TryGetKnownDefinition(
                definition.Id,
                out QuicZeroRttTransportParameterDefinition resolved));
            Assert.Equal(definition.Id, resolved.Id);
            Assert.Equal(definition.Name, resolved.Name);
            Assert.Equal(definition.MemoryRequirement, resolved.MemoryRequirement);
        }

        ulong[] unknownIds = [0x11, 0x12, 0x1F, 0x21, ulong.MaxValue];
        foreach (ulong unknownId in unknownIds)
        {
            Assert.False(QuicZeroRttTransportParameterPolicy.TryGetKnownDefinition(
                unknownId,
                out _));
        }
    }
}
