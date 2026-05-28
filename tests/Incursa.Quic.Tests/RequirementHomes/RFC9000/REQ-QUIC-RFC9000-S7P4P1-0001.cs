// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0001")]
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
}
