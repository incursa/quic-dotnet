// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpRouteAdvertisementCapsuleTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0127")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_UsesTypeThreeWithLengthAndRanges()
    {
        Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([Range("192.0.2.1", "192.0.2.10", 6)]);
        byte[] encoded = capsule.Encode();

        Assert.Equal(Http3ConnectIpRouteAdvertisementCapsule.CapsuleType, capsule.Type);
        Assert.Equal(0x03, encoded[0]);
        Assert.Equal((byte)capsule.Payload.Length, encoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0127")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_RejectsWrongCapsuleType()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x02, [])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0128")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_EncodesVersionStartEndAndProtocolInOrder()
    {
        Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([Range("192.0.2.1", "192.0.2.10", 6)]);

        Assert.Equal([0x04, 192, 0, 2, 1, 192, 0, 2, 10, 6], capsule.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0128")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsTruncatedRangeLayout()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [0x04, 192, 0, 2, 1])));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0129")]
    [Requirement("REQ-QUIC-RFC9484-0130")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("192.0.2.1", "192.0.2.10", 4)]
    [InlineData("2001:db8::1", "2001:db8::10", 6)]
    public void RouteRange_EncodesIpVersionAsUnsignedByteFourOrSix(string start, string end, int expectedVersion)
    {
        Http3ConnectIpRouteRange range = Range(start, end, 6);

        Assert.Equal(expectedVersion, range.IpVersion);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0129")]
    [Requirement("REQ-QUIC-RFC9484-0130")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsUnsupportedIpVersion()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [0x05, 192, 0, 2, 1, 192, 0, 2, 10, 6])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0131")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_UsesThirtyTwoBitIpv4StartAndEndAddresses()
    {
        Assert.Equal(10, Http3ConnectIpRouteAdvertisementCapsule.Create([Range("192.0.2.1", "192.0.2.10", 6)]).Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0131")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsTruncatedIpv4EndAddress()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [0x04, 192, 0, 2, 1, 192, 0, 2])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0132")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_UsesOneHundredTwentyEightBitIpv6StartAndEndAddresses()
    {
        Assert.Equal(34, Http3ConnectIpRouteAdvertisementCapsule.Create([Range("2001:db8::1", "2001:db8::10", 6)]).Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0132")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsTruncatedIpv6EndAddress()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [0x06, 0x20, 0x01])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0133")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_AllowsStartLessThanOrEqualToEnd()
    {
        Assert.Equal(IPAddress.Parse("192.0.2.10"), Range("192.0.2.1", "192.0.2.10", 6).EndAddress);
        Assert.Equal(IPAddress.Parse("192.0.2.1"), Range("192.0.2.1", "192.0.2.1", 6).EndAddress);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0133")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsStartGreaterThanEnd()
    {
        Assert.Throws<ArgumentException>(() => Range("192.0.2.10", "192.0.2.1", 6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0134")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_EncodesIpProtocolAsUnsignedByte()
    {
        Assert.Equal(132, Range("192.0.2.1", "192.0.2.10", 132).IpProtocol);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0134")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_RejectsProtocolOutsideUnsignedByte()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Range("192.0.2.1", "192.0.2.10", 256));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0135")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_ProtocolZeroAllowsAllProtocols()
    {
        Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", 0);

        Assert.True(range.AllowsProtocol(6));
        Assert.True(range.AllowsProtocol(132));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0135")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_NonZeroProtocolDoesNotAllowAllProtocols()
    {
        Assert.False(Range("192.0.2.1", "192.0.2.10", 17).AllowsProtocol(6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0136")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteRange_NonZeroProtocolRepresentsNextHeaderValue()
    {
        Assert.True(Range("192.0.2.1", "192.0.2.10", 17).AllowsProtocol(17));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0136")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_NonZeroProtocolRejectsDifferentNonIcmpProtocol()
    {
        Assert.False(Range("192.0.2.1", "192.0.2.10", 17).AllowsProtocol(132));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0137")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber)]
    [InlineData(Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber)]
    public void RouteRange_AlwaysAllowsIcmpTraffic(int protocol)
    {
        Assert.True(Range("192.0.2.1", "192.0.2.10", 17).AllowsProtocol(protocol));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0137")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteRange_IcmpExceptionDoesNotAllowEveryProtocol()
    {
        Assert.False(Range("192.0.2.1", "192.0.2.10", 17).AllowsProtocol(132));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0138")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_ParsesWellFormedCapsule()
    {
        Http3ConnectIpRouteRange parsed = Assert.Single(Http3ConnectIpRouteAdvertisementCapsule.Parse(
            Http3ConnectIpRouteAdvertisementCapsule.Create([Range("192.0.2.1", "192.0.2.10", 6)])));

        Assert.Equal(IPAddress.Parse("192.0.2.1"), parsed.StartAddress);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0138")]
    [Requirement("REQ-QUIC-RFC9484-0144")]
    [Requirement("REQ-QUIC-RFC9484-0146")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_MalformedCapsuleFieldsAbortRequestStream()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [0x04, 192])));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.ShouldAbortRequestStreamForInvalidAdvertisement(advertisementValid: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0139")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_LatestCapsuleSupersedesPriorRoutes()
    {
        Http3ConnectIpRouteRange[] latest = [Range("192.0.2.20", "192.0.2.30", 6)];

        Http3ConnectIpRouteRange[] applied = Http3ConnectIpRouteAdvertisementCapsule.ApplySupersedingAdvertisement([Range("192.0.2.1", "192.0.2.10", 6)], latest);

        Assert.Equal(latest[0].StartAddress, applied[0].StartAddress);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0139")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_DoesNotMergePriorRoutesWhenSuperseded()
    {
        Http3ConnectIpRouteRange[] applied = Http3ConnectIpRouteAdvertisementCapsule.ApplySupersedingAdvertisement([Range("192.0.2.1", "192.0.2.10", 6)], []);

        Assert.Empty(applied);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0140")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_MissingPriorRangeIsWithdrawn()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.IsWithdrawn(Range("192.0.2.1", "192.0.2.10", 6), []));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0140")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_PresentPriorRangeIsNotWithdrawn()
    {
        Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", 6);

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.IsWithdrawn(range, [range]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0141")]
    [Requirement("REQ-QUIC-RFC9484-0142")]
    [Requirement("REQ-QUIC-RFC9484-0143")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_AcceptsOrderedNonOverlappingRoutes()
    {
        Http3ConnectIpRouteRange[] ranges =
        [
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.20", "192.0.2.30", 6),
            Range("192.0.2.1", "192.0.2.10", 17),
            Range("2001:db8::1", "2001:db8::10", 6),
        ];

        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping(ranges));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0141")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_RejectsRoutesOutOfIpVersionOrder()
    {
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([Range("2001:db8::1", "2001:db8::10", 6), Range("192.0.2.1", "192.0.2.10", 6)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0142")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_RejectsRoutesOutOfProtocolOrder()
    {
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([Range("192.0.2.1", "192.0.2.10", 17), Range("192.0.2.20", "192.0.2.30", 6)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0143")]
    [Requirement("REQ-QUIC-RFC9484-0145")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RouteAdvertisement_RejectsOverlappingRoutesWithSameVersionAndProtocol()
    {
        Http3ConnectIpRouteRange[] ranges = [Range("192.0.2.1", "192.0.2.10", 6), Range("192.0.2.10", "192.0.2.20", 6)];

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping(ranges));
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.CanSendRouteAdvertisement(ranges));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0144")]
    [Requirement("REQ-QUIC-RFC9484-0146")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_DoesNotAbortForValidAdvertisement()
    {
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.ShouldAbortRequestStreamForInvalidAdvertisement(advertisementValid: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0145")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_CanSendNonOverlappingRoutes()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.CanSendRouteAdvertisement([Range("192.0.2.1", "192.0.2.10", 6), Range("192.0.2.20", "192.0.2.30", 6)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0147")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RouteAdvertisement_MayValidateRoutes()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.MayValidateRoutes);
    }

    [Fact]
    [Requirement("RFC9484-S4-8-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtocolPolicy_MayRejectExtensionHeaderProtocolNumbers()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.MayRejectExtensionHeaderProtocolNumber(43));
    }

    [Fact]
    [Requirement("RFC9484-S4-8-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolPolicy_DoesNotRejectOrdinaryTransportProtocolNumbersAsExtensions()
    {
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.MayRejectExtensionHeaderProtocolNumber(6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0149")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProtocolPolicy_WalksExtensionHeadersToOutermostNonExtensionProtocol()
    {
        Assert.Equal(6, Http3ConnectIpRouteAdvertisementCapsule.SelectOutermostNonExtensionProtocol([0, 43, 6]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0149")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtocolPolicy_DoesNotStopAtExtensionHeaderProtocol()
    {
        Assert.NotEqual(43, Http3ConnectIpRouteAdvertisementCapsule.SelectOutermostNonExtensionProtocol([43, 17]));
    }

    private static Http3ConnectIpRouteRange Range(string startAddress, string endAddress, int protocol)
    {
        return new Http3ConnectIpRouteRange(IPAddress.Parse(startAddress), IPAddress.Parse(endAddress), protocol);
    }
}
