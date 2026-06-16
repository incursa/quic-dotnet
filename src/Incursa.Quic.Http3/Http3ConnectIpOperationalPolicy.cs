// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Provides RFC 9484 CONNECT-IP operational, congestion, DSCP, security, and registry policy helpers.
/// </summary>
public static class Http3ConnectIpOperationalPolicy
{
    private const string ExpertReviewRegistrationPolicyValue = "Expert Review";

    /// <summary>
    /// Indicates that IP proxies should avoid increasing IP traffic burstiness.
    /// </summary>
    public const bool AvoidIncreasingBurstiness = true;

    /// <summary>
    /// Indicates whether IP proxies can queue packets only to increase batching.
    /// </summary>
    public const bool QueuePacketsToIncreaseBatchingAllowed = false;

    /// <summary>
    /// Indicates that HTTP/3 is preferred for IP proxying.
    /// </summary>
    public const bool PreferHttp3ForIpProxying = true;

    /// <summary>
    /// Indicates whether oversized IP packets should be sent in DATAGRAM capsules when QUIC DATAGRAM is in use.
    /// </summary>
    public const bool OversizedIpPacketDatagramCapsuleFallbackAllowedWhenQuicDatagramInUse = false;

    /// <summary>
    /// Indicates whether ECN support can be signaled when congestion control is disabled.
    /// </summary>
    public const bool EcnSupportSignalAllowedWhenCongestionControlDisabled = false;

    /// <summary>
    /// Gets the IP ECN codepoint to use when congestion control is disabled.
    /// </summary>
    public const Http3ConnectIpEcnCodepoint EcnCodepointWhenCongestionControlDisabled = Http3ConnectIpEcnCodepoint.NotEct;

    /// <summary>
    /// Indicates whether inner DSCP values can be copied to the outer header under outer congestion control.
    /// </summary>
    public const bool CopyInnerDscpToOuterHeaderAllowedUnderOuterCongestionControl = false;

    /// <summary>
    /// Indicates that IP proxying should be restricted to authenticated users.
    /// </summary>
    public const bool RestrictIpProxyingToAuthenticatedUsers = true;

    /// <summary>
    /// Indicates that persistent per-client address assignment should be avoided when possible.
    /// </summary>
    public const bool AvoidPersistentPerClientAddressAssignment = true;

    /// <summary>
    /// Indicates that endpoints follow BCP 38 source-spoofing prevention recommendations.
    /// </summary>
    public const bool FollowBcp38SourceAddressSpoofingPrevention = true;

    /// <summary>
    /// Gets the required MASQUE URI Suffixes registry policy.
    /// </summary>
    public const string ExpertReviewRegistrationPolicy = ExpertReviewRegistrationPolicyValue;

    /// <summary>
    /// Returns true when a configuration exchange should define a capsule type.
    /// </summary>
    public static bool ShouldDefineCapsuleTypeForConfigurationExchange(bool configurationExchangeNeeded)
    {
        return configurationExchangeNeeded;
    }

    /// <summary>
    /// Returns true when congestion control can be disabled for DATAGRAM-only IP packets.
    /// </summary>
    public static bool CanDisableCongestionControlForDatagramOnlyIpPackets(bool packetContainsOnlyQuicDatagramFramesEncapsulatingIpPackets)
    {
        return packetContainsOnlyQuicDatagramFramesEncapsulatingIpPackets;
    }

    /// <summary>
    /// Returns true when HTTP/3 and QUIC DATAGRAM are available for IP packets.
    /// </summary>
    public static bool ShouldTransmitIpPacketsInQuicDatagramFrames(bool usingHttp3, bool quicDatagramEnabled)
    {
        return usingHttp3 && quicDatagramEnabled;
    }

    /// <summary>
    /// Returns true when an IP packet fits the QUIC DATAGRAM path limit.
    /// </summary>
    public static bool CanFitInQuicDatagram(int ipPacketLength, int quicConnectionDatagramPayloadLimit, int pathMtuPayloadLimit)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(ipPacketLength);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(quicConnectionDatagramPayloadLimit);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(pathMtuPayloadLimit);
        return ipPacketLength <= Math.Min(quicConnectionDatagramPayloadLimit, pathMtuPayloadLimit);
    }

    /// <summary>
    /// Returns true when an IP packet is too large for the QUIC DATAGRAM path.
    /// </summary>
    public static bool ShouldDropOversizedIpPacket(int ipPacketLength, int quicConnectionDatagramPayloadLimit, int pathMtuPayloadLimit)
    {
        return !CanFitInQuicDatagram(ipPacketLength, quicConnectionDatagramPayloadLimit, pathMtuPayloadLimit);
    }

    /// <summary>
    /// Returns true when Packet Too Big feedback should be sent for an oversized IP packet.
    /// </summary>
    public static bool ShouldSendPacketTooBigForOversizedIpPacket(int ipPacketLength, int quicConnectionDatagramPayloadLimit, int pathMtuPayloadLimit)
    {
        return ShouldDropOversizedIpPacket(ipPacketLength, quicConnectionDatagramPayloadLimit, pathMtuPayloadLimit);
    }

    /// <summary>
    /// Returns true when traffic differentiation by DSCP markings is permitted.
    /// </summary>
    public static bool CanDifferentiateTrafficByDscp(bool configuredAsDifferentiatedServicesDomain)
    {
        return configuredAsDifferentiatedServicesDomain;
    }

    /// <summary>
    /// Returns true when DSCP markings are equivalent under outer congestion control.
    /// </summary>
    public static bool DscpMarkingAllowedUnderOuterCongestionControl(bool equivalentForwardingBehavior)
    {
        return equivalentForwardingBehavior;
    }

    /// <summary>
    /// Returns true when DSCP values can be translated to the outer header.
    /// </summary>
    public static bool CanTranslateDscpToOuterHeader(bool usingQuicDatagrams, bool outerCongestionControlDisabled)
    {
        return usingQuicDatagrams && outerCongestionControlDisabled;
    }

    /// <summary>
    /// Returns true when inner packets can be coalesced into one outer packet.
    /// </summary>
    public static bool CanCoalesceInnerPackets(bool sameDscpMarkingOrEquivalentTrafficClass)
    {
        return sameDscpMarkingOrEquivalentTrafficClass;
    }

    /// <summary>
    /// Returns true when a user can use IP proxying.
    /// </summary>
    public static bool CanUseIpProxying(bool authenticatedUser)
    {
        return authenticatedUser;
    }

    /// <summary>
    /// Returns true when persistent per-client address assignment should be used.
    /// </summary>
    public static bool ShouldUsePersistentPerClientAddressAssignment(bool possibleToAvoidPersistentAssignment)
    {
        return !possibleToAvoidPersistentAssignment;
    }

    /// <summary>
    /// Returns true when an ICMP packet destined for the shared external IP can be forwarded to clients.
    /// </summary>
    public static bool CanForwardIcmpPacketToClients(bool destinedForSharedExternalIpAddress)
    {
        return destinedForSharedExternalIpAddress;
    }

    /// <summary>
    /// Returns true when shared-address ICMP forwarding is scoped to the invoking packet.
    /// </summary>
    public static bool CanForwardSharedExternalIcmpToClient(bool invokingPacketScopeMatchesClient)
    {
        return invokingPacketScopeMatchesClient;
    }

    /// <summary>
    /// Returns true when opportunistic IP packet sending is permitted for the HTTP version.
    /// </summary>
    public static bool CanUseOpportunisticIpPacketSending(bool usingHttp1x)
    {
        return !usingHttp1x;
    }

    /// <summary>
    /// Returns true when an HTTP/2 or HTTP/3 to HTTP/1.1 intermediary can forward received capsules.
    /// </summary>
    public static bool CanForwardCapsulesWhenReencodingToHttp11(bool successfulIpProxyingResponseParsed)
    {
        return successfulIpProxyingResponseParsed;
    }

    /// <summary>
    /// Returns true when a MASQUE URI suffix registry path segment is valid.
    /// </summary>
    public static bool IsValidRegistryPathSegment(string pathSegment)
    {
        if (string.IsNullOrEmpty(pathSegment))
        {
            return false;
        }

        for (int index = 0; index < pathSegment.Length; index++)
        {
            if (!IsTokenCharacter(pathSegment[index]))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns true when registry path segments are distinct.
    /// </summary>
    public static bool RegistryPathSegmentsAreDistinct(IEnumerable<string> pathSegments)
    {
        ArgumentNullException.ThrowIfNull(pathSegments);
        HashSet<string> seen = [];
        foreach (string pathSegment in pathSegments)
        {
            if (!seen.Add(pathSegment))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Returns true when a MASQUE URI suffix registration request should be approved by designated experts.
    /// </summary>
    public static bool ShouldApproveMasqueUriSuffixRequest(bool conflictsWithExistingOrFutureIetfWork, bool useCaseRelevantToProxying)
    {
        return !conflictsWithExistingOrFutureIetfWork && useCaseRelevantToProxying;
    }

    private static bool IsTokenCharacter(char value)
    {
        return value is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~';
    }
}
