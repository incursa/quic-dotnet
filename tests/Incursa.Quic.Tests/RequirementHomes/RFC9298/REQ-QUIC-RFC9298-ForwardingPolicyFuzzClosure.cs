// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_ForwardingPolicyFuzzClosure
{
    [Fact]
    [Requirement("RFC9298-S6-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyAvoidsIncreasingBurstiness()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.AvoidIncreasingBurstiness);
    }

    [Fact]
    [Requirement("RFC9298-S6-P1-S2-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyDoesNotQueueOnlyToIncreaseBatching()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.QueuePacketsToIncreaseBatchingAllowed);
    }

    [Fact]
    [Requirement("RFC9298-S6-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlDisablesOnlyWithOutOfBandCertainty()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.CanDisableCongestionControl(innerTrafficKnownCongestionControlledWithCertainty: true));
        Assert.False(Http3ConnectUdpForwardingPolicy.CanDisableCongestionControl(innerTrafficKnownCongestionControlledWithCertainty: false));
    }

    [Fact]
    [Requirement("RFC9298-S6-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlDisabledDoesNotSignalEcnSupport()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("RFC9298-S6-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlDisabledMarksIpHeadersNotEct()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("RFC9298-S6-P3-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EcnFeedbackContinuesOnlyWhenPeerMayUseCongestionControl()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.CanContinueReportingEcnFeedback(peerMayNotHaveDisabledCongestionControl: true));
        Assert.False(Http3ConnectUdpForwardingPolicy.CanContinueReportingEcnFeedback(peerMayNotHaveDisabledCongestionControl: false));
    }

    [Fact]
    [Requirement("RFC9298-S6-P4-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyingPrefersHttp3ForQuicDatagramSupport()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.PreferHttp3ForUdpProxying);
    }

    [Fact]
    [Requirement("RFC9298-S6-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_Http3WithQuicDatagramTransmitsUdpPayloadsInQuicDatagramFrames()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldTransmitUdpPayloadsInQuicDatagramFrames(usingHttp3: true, quicDatagramEnabled: true));
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldTransmitUdpPayloadsInQuicDatagramFrames(usingHttp3: false, quicDatagramEnabled: true));
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldTransmitUdpPayloadsInQuicDatagramFrames(usingHttp3: true, quicDatagramEnabled: false));
    }

    [Fact]
    [Requirement("RFC9298-S6-1-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_QuicDatagramFramesCarryPayloadsWithinConnectionAndPathLimit()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.CanFitInQuicDatagram(udpPayloadLength: 1199, quicDatagramPayloadLimit: 1200));
        Assert.True(Http3ConnectUdpForwardingPolicy.CanFitInQuicDatagram(udpPayloadLength: 1200, quicDatagramPayloadLimit: 1200));
        Assert.False(Http3ConnectUdpForwardingPolicy.CanFitInQuicDatagram(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("RFC9298-S6-1-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OversizedQuicDatagramPayloadIsNotSentAsDatagramCapsuleFallback()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.OversizedPayloadDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0109")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyDropsOversizedUdpPayload()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldDropOversizedUdpPayload(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldDropOversizedUdpPayload(udpPayloadLength: 1200, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0110")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxySendsIcmpPacketTooBigForOversizedTargetPayload()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldSendIcmpPacketTooBigForOversizedTargetPayload(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldSendIcmpPacketTooBigForOversizedTargetPayload(udpPayloadLength: 1200, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0111")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyingTunnelDoesNotIncludeInnerIpHeader()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.TunnelIncludesInnerIpHeader);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0112")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyRetainsControlOfOutboundUdpEcnCodepoints()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ClientControlOutboundUdpEcnCodepointsAllowed);
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.OutboundUdpEcnCodepoint);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0113")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyDoesNotCommunicatePerPacketTargetMarkings()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CommunicatePerPacketTargetMarkingsToClientAllowed);
    }

    [Fact]
    [Requirement("RFC9298-S6-2-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyIgnoresEcnBitsFromTargetPackets()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.IgnoreTargetEcnBits);
    }

    [Fact]
    [Requirement("RFC9298-S6-2-P3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxySetsTargetBoundUdpPacketsToNotEct()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.OutboundUdpEcnCodepoint);
    }
}
