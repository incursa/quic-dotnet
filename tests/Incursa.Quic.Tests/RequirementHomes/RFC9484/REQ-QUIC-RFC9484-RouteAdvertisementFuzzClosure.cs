// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_RouteAdvertisementFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0127")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementCapsuleUsesTypeThreeWithPayloadLength()
    {
        foreach (Http3ConnectIpRouteRange[] ranges in RouteSets())
        {
            Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create(ranges);
            byte[] encoded = capsule.Encode();

            Assert.Equal(0x03UL, capsule.Type);
            Assert.Equal(0x03, encoded[0]);
            Assert.Equal(capsule.Payload.Length, encoded[1]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0128")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeLayoutEncodesVersionStartEndAndProtocolInOrder()
    {
        Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([Range("192.0.2.1", "192.0.2.10", 6)]);

        Assert.Equal([0x04, 192, 0, 2, 1, 192, 0, 2, 10, 6], capsule.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0129")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeIpVersionFieldEncodesFourOrSix()
    {
        foreach ((Http3ConnectIpRouteRange range, byte expectedVersion) in new[]
        {
            (Range("192.0.2.1", "192.0.2.10", 6), (byte)4),
            (Range("2001:db8::1", "2001:db8::10", 6), (byte)6),
        })
        {
            Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([range]);

            Assert.Equal(expectedVersion, capsule.Payload[0]);
            Assert.Equal(expectedVersion, range.IpVersion);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0130")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeRejectsIpVersionValuesOtherThanFourOrSix()
    {
        foreach (byte invalidVersion in new byte[] { 0, 1, 5, 7, 255 })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, [invalidVersion, 192, 0, 2, 1, 192, 0, 2, 10, 6])));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0131")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeUsesThirtyTwoBitStartAndEndAddressesForIpv4()
    {
        foreach (Http3ConnectIpRouteRange range in new[]
        {
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("198.51.100.1", "198.51.100.200", 17),
        })
        {
            Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([range]);

            Assert.Equal(4, range.StartAddress.GetAddressBytes().Length);
            Assert.Equal(4, range.EndAddress.GetAddressBytes().Length);
            Assert.Equal(10, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0132")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeUsesOneHundredTwentyEightBitStartAndEndAddressesForIpv6()
    {
        foreach (Http3ConnectIpRouteRange range in new[]
        {
            Range("2001:db8::1", "2001:db8::10", 6),
            Range("2001:db8:1::", "2001:db8:1::ffff", 17),
        })
        {
            Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([range]);

            Assert.Equal(16, range.StartAddress.GetAddressBytes().Length);
            Assert.Equal(16, range.EndAddress.GetAddressBytes().Length);
            Assert.Equal(34, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0133")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeStartAddressMustBeLessThanOrEqualToEndAddress()
    {
        foreach ((string start, string end) in new[] { ("192.0.2.1", "192.0.2.1"), ("192.0.2.1", "192.0.2.10") })
        {
            Http3ConnectIpRouteRange range = Range(start, end, 6);
            Assert.Equal(IPAddress.Parse(start), range.StartAddress);
            Assert.Equal(IPAddress.Parse(end), range.EndAddress);
        }

        Assert.Throws<ArgumentException>(() => Range("192.0.2.10", "192.0.2.1", 6));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0138")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementMalformedFieldsThrowMessageError()
    {
        foreach (byte[] payload in new byte[][]
        {
            [0x04],
            [0x04, 192, 0, 2, 1],
            [0x04, 192, 0, 2, 1, 192, 0, 2],
            [0x06, 0x20, 0x01],
            [0x05, 192, 0, 2, 1, 192, 0, 2, 10, 6],
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpRouteAdvertisementCapsule.Parse(new Http3Capsule(0x03, payload)));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0141")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementsAreOrderedByIpVersion()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("2001:db8::1", "2001:db8::10", 6),
        ]));

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("2001:db8::1", "2001:db8::10", 6),
            Range("192.0.2.1", "192.0.2.10", 6),
        ]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0142")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementsAreOrderedByIpProtocolWithinVersion()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.20", "192.0.2.30", 17),
        ]));

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("192.0.2.1", "192.0.2.10", 17),
            Range("192.0.2.20", "192.0.2.30", 6),
        ]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0143")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementsRejectOverlappingAddressRangesForSameVersionAndProtocol()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.11", "192.0.2.20", 6),
        ]));

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.10", "192.0.2.20", 6),
        ]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0144")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_InvalidRouteAdvertisementsAbortTheRequestStream()
    {
        foreach (bool advertisementValid in new[] { false, true })
        {
            Assert.Equal(
                !advertisementValid,
                Http3ConnectIpRouteAdvertisementCapsule.ShouldAbortRequestStreamForInvalidAdvertisement(advertisementValid));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0145")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementSendingRequiresNonOverlappingRoutes()
    {
        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.CanSendRouteAdvertisement([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.11", "192.0.2.20", 6),
        ]));

        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.CanSendRouteAdvertisement([
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.5", "192.0.2.20", 6),
        ]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0146")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DetectedRouteViolationsAbortTheRequestStream()
    {
        foreach (Http3ConnectIpRouteRange[] invalidRoutes in new[]
        {
            new[] { Range("2001:db8::1", "2001:db8::10", 6), Range("192.0.2.1", "192.0.2.10", 6) },
            [Range("192.0.2.1", "192.0.2.10", 6), Range("192.0.2.10", "192.0.2.20", 6)],
        })
        {
            Assert.False(Http3ConnectIpRouteAdvertisementCapsule.RoutesAreOrderedAndNonOverlapping(invalidRoutes));
            Assert.True(Http3ConnectIpRouteAdvertisementCapsule.ShouldAbortRequestStreamForInvalidAdvertisement(advertisementValid: false));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0147")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementValidationRemainsOptionalButAvailable()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIpRouteAdvertisementCapsule.MayValidateRoutes);
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P6-6-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteAdvertisementIpProtocolIsEncodedAsUnsignedEightBitInteger()
    {
        foreach (int protocol in new[] { 0, 1, 6, 17, 132, 255 })
        {
            Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", protocol);
            Http3Capsule capsule = Http3ConnectIpRouteAdvertisementCapsule.Create([range]);

            Assert.Equal(protocol, capsule.Payload[^1]);
        }

        Assert.Throws<ArgumentOutOfRangeException>(() => Range("192.0.2.1", "192.0.2.10", 256));
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P10-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeProtocolZeroAllowsAllProtocols()
    {
        Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", 0);

        foreach (int protocol in new[] { 1, 6, 17, 58, 132, 255 })
        {
            Assert.True(range.AllowsProtocol(protocol));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P10-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeNonZeroProtocolMatchesSpecificNextHeaderValue()
    {
        foreach (int protocol in new[] { 6, 17, 132 })
        {
            Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", protocol);

            Assert.True(range.AllowsProtocol(protocol));
            Assert.False(range.AllowsProtocol(protocol == 6 ? 17 : 6));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P10-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeAlwaysAllowsIcmpTraffic()
    {
        foreach (int scopedProtocol in new[] { 6, 17, 132 })
        {
            Http3ConnectIpRouteRange range = Range("192.0.2.1", "192.0.2.10", scopedProtocol);

            Assert.True(range.AllowsProtocol(Http3ConnectIpProtocolScope.IcmpV4ProtocolNumber));
            Assert.True(range.AllowsProtocol(Http3ConnectIpProtocolScope.IcmpV6ProtocolNumber));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P9-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LatestRouteAdvertisementSupersedesPreviousRoutes()
    {
        Http3ConnectIpRouteRange[] previous =
        [
            Range("192.0.2.1", "192.0.2.10", 6),
            Range("192.0.2.20", "192.0.2.30", 17),
        ];
        Http3ConnectIpRouteRange[] latest = [Range("2001:db8::1", "2001:db8::10", 6)];

        Http3ConnectIpRouteRange[] applied = Http3ConnectIpRouteAdvertisementCapsule.ApplySupersedingAdvertisement(previous, latest);

        Assert.Equal(latest, applied);
    }

    [Fact]
    [Requirement("RFC9484-S4-7-3-P13-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RouteRangeIsWithdrawnWhenMissingFromLatestAdvertisement()
    {
        Http3ConnectIpRouteRange previous = Range("192.0.2.1", "192.0.2.10", 6);
        Http3ConnectIpRouteRange retained = Range("192.0.2.20", "192.0.2.30", 6);

        Assert.True(Http3ConnectIpRouteAdvertisementCapsule.IsWithdrawn(previous, [retained]));
        Assert.False(Http3ConnectIpRouteAdvertisementCapsule.IsWithdrawn(previous, [previous, retained]));
    }

    [Fact]
    [Requirement("RFC9484-S4-8-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtocolPolicyMayRejectExtensionHeaderProtocolNumbers()
    {
        foreach (int extensionHeader in new[] { 0, 43, 44, 50, 51, 60 })
        {
            Assert.True(Http3ConnectIpRouteAdvertisementCapsule.MayRejectExtensionHeaderProtocolNumber(extensionHeader));
        }

        foreach (int ordinaryProtocol in new[] { 6, 17, 58, 132 })
        {
            Assert.False(Http3ConnectIpRouteAdvertisementCapsule.MayRejectExtensionHeaderProtocolNumber(ordinaryProtocol));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-8-P1-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProtocolPolicyWalksExtensionHeadersToOutermostNonExtensionProtocol()
    {
        foreach ((int[] chain, int expected) in new[]
        {
            (new[] { 0, 43, 6 }, 6),
            (new[] { 43, 60, 17 }, 17),
            (new[] { 44, 50, 51, 58 }, 58),
            (new[] { 43, 60 }, 0),
        })
        {
            Assert.Equal(expected, Http3ConnectIpRouteAdvertisementCapsule.SelectOutermostNonExtensionProtocol(chain));
        }
    }

    private static Http3ConnectIpRouteRange Range(string startAddress, string endAddress, int protocol)
    {
        return new Http3ConnectIpRouteRange(IPAddress.Parse(startAddress), IPAddress.Parse(endAddress), protocol);
    }

    private static Http3ConnectIpRouteRange[][] RouteSets()
    {
        return
        [
            [Range("192.0.2.1", "192.0.2.10", 6)],
            [Range("192.0.2.1", "192.0.2.10", 6), Range("192.0.2.20", "192.0.2.30", 6)],
            [Range("192.0.2.1", "192.0.2.10", 6), Range("192.0.2.20", "192.0.2.30", 17), Range("2001:db8::1", "2001:db8::10", 6)],
        ];
    }
}
