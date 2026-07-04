// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpOperationalPolicyTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0186")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DefinesCapsuleTypesForConfigurationExchange()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldDefineCapsuleTypeForConfigurationExchange(configurationExchangeNeeded: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0186")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotRequireCapsuleTypeWithoutConfigurationExchange()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldDefineCapsuleTypeForConfigurationExchange(configurationExchangeNeeded: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0187")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AvoidsIncreasingIpTrafficBurstiness()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.AvoidIncreasingBurstiness);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0187")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotPermitIncreasedBurstiness()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.AvoidIncreasingBurstiness);
    }

    [Fact]
    [Requirement("RFC9484-S10-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DoesNotQueuePacketsOnlyToIncreaseBatching()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.QueuePacketsToIncreaseBatchingAllowed);
    }

    [Fact]
    [Requirement("RFC9484-S10-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsBatchingOnlyQueuePermission()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.QueuePacketsToIncreaseBatchingAllowed);
    }

    [Fact]
    [Requirement("RFC9484-S10-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_CanDisableCongestionControlForDatagramOnlyIpPackets()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanDisableCongestionControlForDatagramOnlyIpPackets(packetContainsOnlyQuicDatagramFramesEncapsulatingIpPackets: true));
    }

    [Fact]
    [Requirement("RFC9484-S10-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotDisableCongestionControlForMixedPackets()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanDisableCongestionControlForDatagramOnlyIpPackets(packetContainsOnlyQuicDatagramFramesEncapsulatingIpPackets: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0190")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_PrefersHttp3ForIpProxying()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.PreferHttp3ForIpProxying);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0190")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotPreferNonHttp3IpProxying()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.PreferHttp3ForIpProxying);
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_UsesQuicDatagramFramesWhenAvailable()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldTransmitIpPacketsInQuicDatagramFrames(usingHttp3: true, quicDatagramEnabled: true));
    }

    [Theory]
    [Requirement("RFC9484-S10-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void OperationalPolicy_DoesNotUseQuicDatagramFramesWhenUnavailable(bool usingHttp3, bool quicDatagramEnabled)
    {
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldTransmitIpPacketsInQuicDatagramFrames(usingHttp3, quicDatagramEnabled));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0192")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AllowsIpPacketsWithinConnectionAndPmtuLimit()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanFitInQuicDatagram(ipPacketLength: 1200, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0192")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsIpPacketsBeyondConnectionOrPmtuLimit()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanFitInQuicDatagram(ipPacketLength: 1281, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DoesNotCapsuleOversizedIpPacketWhenQuicDatagramInUse()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.OversizedIpPacketDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsDatagramCapsuleFallbackForOversizedIpPacket()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.OversizedIpPacketDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DropsOversizedIpPackets()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldDropOversizedIpPacket(ipPacketLength: 1281, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotDropIpPacketsThatFit()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldDropOversizedIpPacket(ipPacketLength: 1280, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0195")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_SendsPacketTooBigForOversizedIpPackets()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldSendPacketTooBigForOversizedIpPacket(ipPacketLength: 1281, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0195")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotSendPacketTooBigForFittingIpPackets()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldSendPacketTooBigForOversizedIpPacket(ipPacketLength: 1280, quicConnectionDatagramPayloadLimit: 1300, pathMtuPayloadLimit: 1280));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0196")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DoesNotSignalEcnWhenCongestionControlDisabled()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0196")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsEcnSupportSignalWhenCongestionControlDisabled()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0197")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_MarksOutsideCongestionControlPacketsNotEct()
    {
        Assert.Equal(Http3ConnectIpEcnCodepoint.NotEct, Http3ConnectIpOperationalPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0197")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotUseEctWhenCongestionControlDisabled()
    {
        Assert.Equal(Http3ConnectIpEcnCodepoint.NotEct, Http3ConnectIpOperationalPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AllowsDscpDifferentiationInDiffServDomain()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanDifferentiateTrafficByDscp(configuredAsDifferentiatedServicesDomain: true));
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotDifferentiateDscpOutsideDiffServDomain()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanDifferentiateTrafficByDscp(configuredAsDifferentiatedServicesDomain: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0199")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AllowsEquivalentDscpMarkingsUnderOuterCongestionControl()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.DscpMarkingAllowedUnderOuterCongestionControl(equivalentForwardingBehavior: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0199")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsNonEquivalentDscpMarkingsUnderOuterCongestionControl()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.DscpMarkingAllowedUnderOuterCongestionControl(equivalentForwardingBehavior: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0200")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_DoesNotCopyInnerDscpToOuterHeaderUnderOuterCongestionControl()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CopyInnerDscpToOuterHeaderAllowedUnderOuterCongestionControl);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0200")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsCopyingInnerDscpToOuterHeaderUnderOuterCongestionControl()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CopyInnerDscpToOuterHeaderAllowedUnderOuterCongestionControl);
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_TranslatesDscpForQuicDatagramsOutsideOuterCongestionControl()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanTranslateDscpToOuterHeader(usingQuicDatagrams: true, outerCongestionControlDisabled: true));
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotTranslateDscpWhenOuterCongestionControlApplies()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanTranslateDscpToOuterHeader(usingQuicDatagrams: true, outerCongestionControlDisabled: false));
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_CoalescesOnlyEquivalentDscpTraffic()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanCoalesceInnerPackets(sameDscpMarkingOrEquivalentTrafficClass: true));
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotCoalesceDifferentDscpTraffic()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanCoalesceInnerPackets(sameDscpMarkingOrEquivalentTrafficClass: false));
    }

    [Fact]
    [Requirement("RFC9484-S11-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_RestrictsIpProxyingToAuthenticatedUsers()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.RestrictIpProxyingToAuthenticatedUsers);
        Assert.True(Http3ConnectIpOperationalPolicy.CanUseIpProxying(authenticatedUser: true));
    }

    [Fact]
    [Requirement("RFC9484-S11-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsUnauthenticatedIpProxyingUse()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanUseIpProxying(authenticatedUser: false));
    }

    [Fact]
    [Requirement("RFC9484-S11-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AvoidsPersistentPerClientAddressAssignmentWhenPossible()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.AvoidPersistentPerClientAddressAssignment);
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldUsePersistentPerClientAddressAssignment(possibleToAvoidPersistentAssignment: true));
    }

    [Fact]
    [Requirement("RFC9484-S11-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_AllowsPersistentAddressAssignmentOnlyWhenNotAvoidable()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldUsePersistentPerClientAddressAssignment(possibleToAvoidPersistentAssignment: false));
    }

    [Fact]
    [Requirement("RFC9484-S11-P3-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_FollowsBcp38SourceSpoofingPrevention()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.FollowBcp38SourceAddressSpoofingPrevention);
    }

    [Fact]
    [Requirement("RFC9484-S11-P3-S4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotDisableBcp38SourceSpoofingPrevention()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.FollowBcp38SourceAddressSpoofingPrevention);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0206")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_ForwardsIcmpPacketsDestinedForSharedExternalAddress()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanForwardIcmpPacketToClients(destinedForSharedExternalIpAddress: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0206")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DoesNotForwardIcmpPacketsForOtherAddresses()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanForwardIcmpPacketToClients(destinedForSharedExternalIpAddress: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0207")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_ForwardsSharedExternalIcmpOnlyToMatchingScope()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanForwardSharedExternalIcmpToClient(invokingPacketScopeMatchesClient: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0207")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsSharedExternalIcmpWhenScopeDoesNotMatch()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanForwardSharedExternalIcmpToClient(invokingPacketScopeMatchesClient: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0208")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AllowsOpportunisticSendingOutsideHttp1x()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanUseOpportunisticIpPacketSending(usingHttp1x: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0208")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_ProhibitsOpportunisticSendingInHttp1x()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanUseOpportunisticIpPacketSending(usingHttp1x: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0209")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_ForwardsCapsulesAfterSuccessfulIpProxyingResponse()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.CanForwardCapsulesWhenReencodingToHttp11(successfulIpProxyingResponseParsed: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0209")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_DelaysCapsulesBeforeSuccessfulIpProxyingResponse()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.CanForwardCapsulesWhenReencodingToHttp11(successfulIpProxyingResponseParsed: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0210")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_RequiresExpertReviewRegistrationPolicy()
    {
        Assert.Equal("Expert Review", Http3ConnectIpOperationalPolicy.ExpertReviewRegistrationPolicy);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0210")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsNonExpertReviewRegistrationPolicy()
    {
        Assert.NotEqual("First Come First Served", Http3ConnectIpOperationalPolicy.ExpertReviewRegistrationPolicy);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0211")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_AcceptsTokenRegistryPathSegments()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment("connect-ip"));
        Assert.True(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment("masque_token!#$%&'*+-.^_`|~"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0211")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsNonTokenRegistryPathSegments()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment("connect ip"));
        Assert.False(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment("connect/ip"));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0212")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_RequiresDistinctRegistryPathSegments()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.RegistryPathSegmentsAreDistinct(["connect-ip", "connect-udp"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0212")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsDuplicateRegistryPathSegments()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.RegistryPathSegmentsAreDistinct(["connect-ip", "connect-ip"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0213")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void OperationalPolicy_ApprovesRelevantNonConflictingMasqueUriSuffixRequest()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.ShouldApproveMasqueUriSuffixRequest(conflictsWithExistingOrFutureIetfWork: false, useCaseRelevantToProxying: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0213")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OperationalPolicy_RejectsConflictingOrIrrelevantMasqueUriSuffixRequest()
    {
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldApproveMasqueUriSuffixRequest(conflictsWithExistingOrFutureIetfWork: true, useCaseRelevantToProxying: true));
        Assert.False(Http3ConnectIpOperationalPolicy.ShouldApproveMasqueUriSuffixRequest(conflictsWithExistingOrFutureIetfWork: false, useCaseRelevantToProxying: false));
    }
}
