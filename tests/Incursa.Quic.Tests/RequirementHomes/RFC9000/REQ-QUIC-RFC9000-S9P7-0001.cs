// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P7-0001")]
public sealed class REQ_QUIC_RFC9000_S9P7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Ipv6DatagramSendingResolvesAFlowLabel()
    {
        Assert.True(QuicS9P7FlowLabelTestSupport.TryResolveSourceAddress(
            QuicS9P7FlowLabelTestSupport.PrimaryPath,
            out IPAddress sourceAddress));
        Assert.Equal(IPAddress.Parse("2001:db8::10"), sourceAddress);

        uint flowLabel = QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.PrimaryPath);

        Assert.NotEqual(0U, flowLabel);
        Assert.Equal(flowLabel, QuicS9P7FlowLabelTestSupport.CreateFlowLabel(
            QuicS9P7FlowLabelTestSupport.SeedA,
            QuicS9P7FlowLabelTestSupport.PrimaryPath));
        Assert.InRange(flowLabel, 1U, 0x000F_FFFFU);
    }
}
