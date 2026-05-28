// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P7-0002")]
public sealed class REQ_QUIC_RFC9000_S9P7_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DistinctIpv6PathsProduceDistinctFlowLabels()
    {
        uint firstFlowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.PrimaryPath);
        uint secondFlowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.SecondaryPath);

        Assert.NotEqual(firstFlowLabel, secondFlowLabel);
        Assert.NotEqual(0U, firstFlowLabel);
        Assert.NotEqual(0U, secondFlowLabel);
    }
}
