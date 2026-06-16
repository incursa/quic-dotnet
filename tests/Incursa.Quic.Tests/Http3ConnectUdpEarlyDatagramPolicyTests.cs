// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpEarlyDatagramPolicyTests
{
    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0096")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, Http3ConnectUdpEarlyDatagramAction.BufferTemporarily)]
    [InlineData(false, Http3ConnectUdpEarlyDatagramAction.DropSilently)]
    public void EarlyDatagramPolicy_DropsOrBuffersBeforeRequest(bool temporaryBufferAvailable, Http3ConnectUdpEarlyDatagramAction expected)
    {
        Assert.Equal(expected, Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: false, temporaryBufferAvailable));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0096")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDatagramPolicy_ProcessesDatagramWhenRequestIsKnown()
    {
        Assert.Equal(
            Http3ConnectUdpEarlyDatagramAction.Process,
            Http3ConnectUdpEarlyDatagramPolicy.ClassifyEarlyDatagram(correspondingRequestKnown: true, temporaryBufferAvailable: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0097")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EarlyDatagramPolicy_AppliesBufferingLimitsWhenBuffering()
    {
        Assert.True(Http3ConnectUdpEarlyDatagramPolicy.ShouldApplyBufferingLimits(bufferingEarlyDatagrams: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0097")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDatagramPolicy_DoesNotApplyBufferingLimitsWhenDropping()
    {
        Assert.False(Http3ConnectUdpEarlyDatagramPolicy.ShouldApplyBufferingLimits(bufferingEarlyDatagrams: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0098")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EarlyDatagramPolicy_AllowsClientOptimisticDatagramsBeforeResponse()
    {
        Assert.True(Http3ConnectUdpEarlyDatagramPolicy.ClientMaySendOptimisticDatagramsBeforeResponse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0098")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EarlyDatagramPolicy_DoesNotForbidClientOptimisticDatagramsBeforeResponse()
    {
        Assert.True(Http3ConnectUdpEarlyDatagramPolicy.ClientMaySendOptimisticDatagramsBeforeResponse);
    }
}
