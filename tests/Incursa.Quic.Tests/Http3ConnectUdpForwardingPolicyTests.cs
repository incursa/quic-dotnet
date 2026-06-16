// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpForwardingPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0099")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AvoidsIncreasingUdpBurstiness()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.AvoidIncreasingBurstiness);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0099")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotPermitIncreasedBurstiness()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.AvoidIncreasingBurstiness);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0100")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DoesNotQueuePacketsOnlyToIncreaseBatching()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.QueuePacketsToIncreaseBatchingAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0100")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsBatchingOnlyQueuePermission()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.QueuePacketsToIncreaseBatchingAllowed);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0101")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void ForwardingPolicy_DisablesCongestionControlOnlyWithCertainty(bool certain, bool expected)
    {
        Assert.Equal(expected, Http3ConnectUdpForwardingPolicy.CanDisableCongestionControl(certain));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0101")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotDisableCongestionControlWithoutCertainty()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CanDisableCongestionControl(innerTrafficKnownCongestionControlledWithCertainty: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0102")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DoesNotSignalEcnWhenCongestionControlDisabled()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0102")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsEcnSupportSignalWhenCongestionControlDisabled()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0103")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_MarksIpHeadersNotEctWhenCongestionControlDisabled()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotUseEctWhenCongestionControlDisabled()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0104")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public void ForwardingPolicy_ReportsEcnFeedbackWhenPeerMayStillUseCongestionControl(bool peerMayUseCongestionControl, bool expected)
    {
        Assert.Equal(expected, Http3ConnectUdpForwardingPolicy.CanContinueReportingEcnFeedback(peerMayUseCongestionControl));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0104")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotReportEcnFeedbackWhenNotPermitted()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CanContinueReportingEcnFeedback(peerMayNotHaveDisabledCongestionControl: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0105")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_PrefersHttp3ForUdpProxying()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.PreferHttp3ForUdpProxying);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0105")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotPreferNonHttp3UdpProxying()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.PreferHttp3ForUdpProxying);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0106")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_UsesQuicDatagramFramesWhenAvailable()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldTransmitUdpPayloadsInQuicDatagramFrames(usingHttp3: true, quicDatagramEnabled: true));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9298-0106")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void ForwardingPolicy_DoesNotUseQuicDatagramFramesWhenUnavailable(bool usingHttp3, bool quicDatagramEnabled)
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldTransmitUdpPayloadsInQuicDatagramFrames(usingHttp3, quicDatagramEnabled));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0107")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_AllowsPayloadsWithinQuicDatagramLimit()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.CanFitInQuicDatagram(udpPayloadLength: 1000, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0107")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsPayloadsBeyondQuicDatagramLimit()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CanFitInQuicDatagram(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0108")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DoesNotCapsuleOversizedPayloadWhenQuicDatagramInUse()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.OversizedPayloadDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0108")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsCapsuleFallbackForOversizedQuicDatagramPayload()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.OversizedPayloadDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0109")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DropsOversizedUdpPayloads()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldDropOversizedUdpPayload(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0109")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotDropPayloadsThatFitQuicDatagram()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldDropOversizedUdpPayload(udpPayloadLength: 1200, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0110")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_SendsIcmpPacketTooBigForOversizedTargetPayload()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.ShouldSendIcmpPacketTooBigForOversizedTargetPayload(udpPayloadLength: 1201, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0110")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotSendIcmpPacketTooBigForFittingTargetPayload()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ShouldSendIcmpPacketTooBigForOversizedTargetPayload(udpPayloadLength: 1200, quicDatagramPayloadLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0111")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_TunnelDoesNotIncludeInnerIpHeader()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.TunnelIncludesInnerIpHeader);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0111")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsInnerIpHeaderPresence()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.TunnelIncludesInnerIpHeader);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0112")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_ProxyRetainsControlOfOutboundUdpEcnCodepoints()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ClientControlOutboundUdpEcnCodepointsAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0112")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsClientControlOfOutboundUdpEcnCodepoints()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.ClientControlOutboundUdpEcnCodepointsAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0113")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_DoesNotCommunicatePerPacketTargetMarkingsToClient()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CommunicatePerPacketTargetMarkingsToClientAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0113")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_RejectsPerPacketTargetMarkingCommunication()
    {
        Assert.False(Http3ConnectUdpForwardingPolicy.CommunicatePerPacketTargetMarkingsToClientAllowed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0114")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_IgnoresTargetEcnBits()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.IgnoreTargetEcnBits);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0114")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotPreserveTargetEcnBits()
    {
        Assert.True(Http3ConnectUdpForwardingPolicy.IgnoreTargetEcnBits);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForwardingPolicy_SetsOutboundUdpEcnToNotEct()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.OutboundUdpEcnCodepoint);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0115")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ForwardingPolicy_DoesNotExposeAlternateOutboundUdpEcnCodepoint()
    {
        Assert.Equal(Http3ConnectUdpEcnCodepoint.NotEct, Http3ConnectUdpForwardingPolicy.OutboundUdpEcnCodepoint);
    }
}
