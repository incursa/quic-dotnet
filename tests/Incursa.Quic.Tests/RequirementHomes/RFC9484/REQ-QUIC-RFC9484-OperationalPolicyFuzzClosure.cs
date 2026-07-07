// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_OperationalPolicyFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0190")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OperationalPolicyAlwaysPrefersHttp3ForIpProxying()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIpOperationalPolicy.PreferHttp3ForIpProxying);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0195")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketTooBigFeedbackTracksOversizedIpPackets()
    {
        foreach ((int packetLength, int connectionLimit, int pathLimit, bool expected) in PacketSizeCases())
        {
            Assert.Equal(
                expected,
                Http3ConnectIpOperationalPolicy.ShouldSendPacketTooBigForOversizedIpPacket(packetLength, connectionLimit, pathLimit));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0196")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EcnSupportSignalIsSuppressedWhenCongestionControlIsDisabled()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.False(Http3ConnectIpOperationalPolicy.EcnSupportSignalAllowedWhenCongestionControlDisabled);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0197")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EcnCodepointOutsideCongestionControlIsAlwaysNotEct()
    {
        Http3ConnectIpEcnCodepoint[] codepoints = Enum.GetValues<Http3ConnectIpEcnCodepoint>();

        Assert.Equal([Http3ConnectIpEcnCodepoint.NotEct], codepoints);
        Assert.Equal(Http3ConnectIpEcnCodepoint.NotEct, Http3ConnectIpOperationalPolicy.EcnCodepointWhenCongestionControlDisabled);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0199")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DscpMarkingRequiresEquivalentForwardingBehaviorUnderOuterCongestionControl()
    {
        foreach (bool equivalentForwardingBehavior in new[] { false, true })
        {
            Assert.Equal(
                equivalentForwardingBehavior,
                Http3ConnectIpOperationalPolicy.DscpMarkingAllowedUnderOuterCongestionControl(equivalentForwardingBehavior));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0200")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InnerDscpIsNeverCopiedUnderOuterCongestionControl()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.False(Http3ConnectIpOperationalPolicy.CopyInnerDscpToOuterHeaderAllowedUnderOuterCongestionControl);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0206")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IcmpForwardingRequiresSharedExternalDestination()
    {
        foreach (bool destinedForSharedExternalIpAddress in new[] { false, true })
        {
            Assert.Equal(
                destinedForSharedExternalIpAddress,
                Http3ConnectIpOperationalPolicy.CanForwardIcmpPacketToClients(destinedForSharedExternalIpAddress));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0207")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SharedExternalIcmpForwardingRequiresMatchingInvokingScope()
    {
        foreach (bool invokingPacketScopeMatchesClient in new[] { false, true })
        {
            Assert.Equal(
                invokingPacketScopeMatchesClient,
                Http3ConnectIpOperationalPolicy.CanForwardSharedExternalIcmpToClient(invokingPacketScopeMatchesClient));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0208")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OpportunisticIpPacketSendingIsProhibitedForHttp1x()
    {
        foreach ((bool usingHttp1x, bool expected) in new[] { (true, false), (false, true) })
        {
            Assert.Equal(expected, Http3ConnectIpOperationalPolicy.CanUseOpportunisticIpPacketSending(usingHttp1x));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0209")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CapsuleForwardingWaitsForSuccessfulIpProxyingResponse()
    {
        foreach (bool successfulIpProxyingResponseParsed in new[] { false, true })
        {
            Assert.Equal(
                successfulIpProxyingResponseParsed,
                Http3ConnectIpOperationalPolicy.CanForwardCapsulesWhenReencodingToHttp11(successfulIpProxyingResponseParsed));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0210")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MasqueUriSuffixRegistryPolicyRemainsExpertReview()
    {
        foreach (string rejectedPolicy in new[] { "First Come First Served", "Specification Required", "Standards Action" })
        {
            Assert.NotEqual(Http3ConnectIpOperationalPolicy.ExpertReviewRegistrationPolicy, rejectedPolicy);
        }

        Assert.Equal("Expert Review", Http3ConnectIpOperationalPolicy.ExpertReviewRegistrationPolicy);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0211")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RegistryPathSegmentsUseHttpTokenCharacters()
    {
        foreach (string validSegment in new[] { "connect-ip", "masque_token", "token!#$%&'*+-.^_`|~" })
        {
            Assert.True(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment(validSegment));
        }

        foreach (string invalidSegment in new[] { "", "connect ip", "connect/ip", "connect,ip", "connect:ip" })
        {
            Assert.False(Http3ConnectIpOperationalPolicy.IsValidRegistryPathSegment(invalidSegment));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0212")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RegistryPathSegmentsMustBeDistinct()
    {
        Assert.True(Http3ConnectIpOperationalPolicy.RegistryPathSegmentsAreDistinct(["connect-ip", "connect-udp", "webtransport"]));
        Assert.False(Http3ConnectIpOperationalPolicy.RegistryPathSegmentsAreDistinct(["connect-ip", "connect-ip"]));
        Assert.False(Http3ConnectIpOperationalPolicy.RegistryPathSegmentsAreDistinct(["connect-ip", "connect-udp", "connect-udp"]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0213")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MasqueUriSuffixApprovalRequiresRelevantNonConflictingUseCase()
    {
        foreach ((bool conflicts, bool relevant, bool expected) in new[]
        {
            (false, true, true),
            (true, true, false),
            (false, false, false),
            (true, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpOperationalPolicy.ShouldApproveMasqueUriSuffixRequest(conflicts, relevant));
        }
    }

    [Fact]
    [Requirement("RFC9484-S9-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConfigurationExchangeDefinesCapsuleTypeOnlyWhenExchangeIsNeeded()
    {
        foreach (bool configurationExchangeNeeded in new[] { false, true })
        {
            Assert.Equal(
                configurationExchangeNeeded,
                Http3ConnectIpOperationalPolicy.ShouldDefineCapsuleTypeForConfigurationExchange(configurationExchangeNeeded));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyAvoidsIncreasingBurstiness()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIpOperationalPolicy.AvoidIncreasingBurstiness);
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-P1-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyDoesNotQueueOnlyToIncreaseBatching()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.False(Http3ConnectIpOperationalPolicy.QueuePacketsToIncreaseBatchingAllowed);
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CongestionControlCanBeDisabledOnlyForDatagramOnlyIpPackets()
    {
        foreach (bool datagramOnlyPacket in new[] { false, true })
        {
            Assert.Equal(
                datagramOnlyPacket,
                Http3ConnectIpOperationalPolicy.CanDisableCongestionControlForDatagramOnlyIpPackets(datagramOnlyPacket));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPacketsUseQuicDatagramFramesOnlyWhenHttp3AndDatagramAreAvailable()
    {
        foreach ((bool usingHttp3, bool quicDatagramEnabled, bool expected) in new[]
        {
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpOperationalPolicy.ShouldTransmitIpPacketsInQuicDatagramFrames(usingHttp3, quicDatagramEnabled));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_QuicDatagramPayloadSizeIsBoundedByConnectionAndPathLimits()
    {
        foreach ((int packetLength, int connectionLimit, int pathLimit, bool oversized) in PacketSizeCases())
        {
            Assert.Equal(!oversized, Http3ConnectIpOperationalPolicy.CanFitInQuicDatagram(packetLength, connectionLimit, pathLimit));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OversizedIpPacketsAreNotSentInDatagramCapsulesWhenQuicDatagramIsInUse()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.False(Http3ConnectIpOperationalPolicy.OversizedIpPacketDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse);
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-1-P1-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_OversizedIpPacketsAreDroppedWhenTheyExceedConnectionOrPathLimits()
    {
        foreach ((int packetLength, int connectionLimit, int pathLimit, bool expectedDrop) in PacketSizeCases())
        {
            Assert.Equal(expectedDrop, Http3ConnectIpOperationalPolicy.ShouldDropOversizedIpPacket(packetLength, connectionLimit, pathLimit));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DscpDifferentiationRequiresDifferentiatedServicesDomain()
    {
        foreach (bool configuredAsDifferentiatedServicesDomain in new[] { false, true })
        {
            Assert.Equal(
                configuredAsDifferentiatedServicesDomain,
                Http3ConnectIpOperationalPolicy.CanDifferentiateTrafficByDscp(configuredAsDifferentiatedServicesDomain));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DscpTranslationRequiresQuicDatagramsOutsideOuterCongestionControl()
    {
        foreach ((bool usingQuicDatagrams, bool outerCongestionControlDisabled, bool expected) in new[]
        {
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpOperationalPolicy.CanTranslateDscpToOuterHeader(usingQuicDatagrams, outerCongestionControlDisabled));
        }
    }

    [Fact]
    [Requirement("RFC9484-S10-3-P3-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InnerPacketsCoalesceOnlyForEquivalentDscpTraffic()
    {
        foreach (bool equivalentTrafficClass in new[] { false, true })
        {
            Assert.Equal(equivalentTrafficClass, Http3ConnectIpOperationalPolicy.CanCoalesceInnerPackets(equivalentTrafficClass));
        }
    }

    [Fact]
    [Requirement("RFC9484-S11-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyingUseRequiresAuthenticatedUsers()
    {
        foreach (bool authenticatedUser in new[] { false, true })
        {
            Assert.Equal(authenticatedUser, Http3ConnectIpOperationalPolicy.CanUseIpProxying(authenticatedUser));
            Assert.True(Http3ConnectIpOperationalPolicy.RestrictIpProxyingToAuthenticatedUsers);
        }
    }

    [Fact]
    [Requirement("RFC9484-S11-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PersistentPerClientAddressAssignmentIsUsedOnlyWhenUnavoidable()
    {
        foreach ((bool possibleToAvoid, bool expected) in new[] { (true, false), (false, true) })
        {
            Assert.Equal(expected, Http3ConnectIpOperationalPolicy.ShouldUsePersistentPerClientAddressAssignment(possibleToAvoid));
            Assert.True(Http3ConnectIpOperationalPolicy.AvoidPersistentPerClientAddressAssignment);
        }
    }

    [Fact]
    [Requirement("RFC9484-S11-P3-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SourceAddressSpoofingPreventionPolicyFollowsBcp38()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIpOperationalPolicy.FollowBcp38SourceAddressSpoofingPrevention);
        }
    }

    private static IEnumerable<(int PacketLength, int ConnectionLimit, int PathLimit, bool Oversized)> PacketSizeCases()
    {
        yield return (0, 1200, 1200, false);
        yield return (1199, 1200, 1280, false);
        yield return (1200, 1200, 1280, false);
        yield return (1201, 1200, 1280, true);
        yield return (1279, 1300, 1280, false);
        yield return (1280, 1300, 1280, false);
        yield return (1281, 1300, 1280, true);
    }
}
