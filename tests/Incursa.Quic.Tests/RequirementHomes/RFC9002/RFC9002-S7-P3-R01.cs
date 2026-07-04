// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9002-S7-P3-R01")]
public sealed class REQ_QUIC_RFC9002_S7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SenderFlowControllerUsesTheBuiltInRfc9002ControllerWhenNoAlternateControllerSurfaceExists()
    {
        QuicSenderFlowController sender = new();

        Assert.NotNull(sender.CongestionControlState);
        Assert.DoesNotContain(
            typeof(QuicConnection).Assembly.GetExportedTypes(),
            type => type.Name.Contains("CongestionController", StringComparison.OrdinalIgnoreCase)
                || type.Name.Contains("CongestionControlProvider", StringComparison.OrdinalIgnoreCase));
    }
}
