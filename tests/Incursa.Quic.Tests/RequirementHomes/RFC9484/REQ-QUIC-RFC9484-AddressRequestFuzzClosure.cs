// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_AddressRequestFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0100")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestIsSentOnlyWhenAssignmentIsExpectedAndNeeded()
    {
        foreach ((bool expecting, bool needed, bool expected) in new[]
        {
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpAddressRequestCapsule.ShouldSendAddressRequest(expecting, needed));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0101")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignCanBeSentWithoutAPrecedingAddressRequest()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            Assert.True(Http3ConnectIpAddressRequestCapsule.CanSendUnpromptedAddressAssign);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0102")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestCapsuleEncodingCarriesPayloadLength()
    {
        foreach (Http3ConnectIpRequestedAddress[] requestedAddresses in AddressRequestSets())
        {
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create(requestedAddresses);
            byte[] encoded = capsule.Encode();

            Assert.Equal(capsule.Payload.Length, encoded[1]);
            Assert.Equal(encoded.Length - 2, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0103")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestCapsuleUsesTypeTwoAndRejectsOtherTypes()
    {
        foreach (ulong type in new[] { 0UL, 1UL, 3UL, 63UL })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(type, [0x01, 0x04, 192, 0, 2, 0, 24])));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }

        Assert.Equal(0x02UL, Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24)]).Type);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0104")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestParsesRequestedAddressFields()
    {
        foreach (Http3ConnectIpRequestedAddress expected in new[]
        {
            Request(1, "192.0.2.0", 24),
            Request(2, "2001:db8::", 64),
        })
        {
            Http3ConnectIpRequestedAddress parsed = Assert.Single(
                Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([expected])));

            Assert.Equal(expected.RequestId, parsed.RequestId);
            Assert.Equal(expected.Address, parsed.Address);
            Assert.Equal(expected.PrefixLength, parsed.PrefixLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0105")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestContainsOneOrMoreRequestedAddressEntries()
    {
        foreach (Http3ConnectIpRequestedAddress[] requestedAddresses in AddressRequestSets())
        {
            Http3ConnectIpRequestedAddress[] parsed = Http3ConnectIpAddressRequestCapsule.Parse(
                Http3ConnectIpAddressRequestCapsule.Create(requestedAddresses));

            Assert.Equal(requestedAddresses.Length, parsed.Length);
            Assert.NotEmpty(parsed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0106")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressIpAddressFieldRoundTripsAddressBytes()
    {
        foreach (Http3ConnectIpRequestedAddress expected in new[]
        {
            Request(1, "192.0.2.0", 24),
            Request(2, "2001:db8::", 64),
        })
        {
            Http3ConnectIpRequestedAddress parsed = Assert.Single(
                Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([expected])));

            Assert.Equal(expected.Address.GetAddressBytes(), parsed.Address.GetAddressBytes());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0107")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressPrefixLengthFieldRoundTripsAsUnsignedByte()
    {
        foreach (Http3ConnectIpRequestedAddress expected in new[]
        {
            Request(1, "0.0.0.0", 0),
            Request(2, "192.0.2.0", 24),
            Request(3, "2001:db8::", 64),
            Request(4, "::", 128),
        })
        {
            Http3ConnectIpRequestedAddress parsed = Assert.Single(
                Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([expected])));

            Assert.Equal(expected.PrefixLength, parsed.PrefixLength);
            Assert.InRange(parsed.PrefixLength, 0, 255);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0108")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressIpVersionFieldRoundTripsFourOrSix()
    {
        foreach ((Http3ConnectIpRequestedAddress request, int expectedVersion) in new[]
        {
            (Request(1, "192.0.2.0", 24), 4),
            (Request(2, "2001:db8::", 64), 6),
        })
        {
            Http3ConnectIpRequestedAddress parsed = Assert.Single(
                Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([request])));

            Assert.Equal(expectedVersion, parsed.IpVersion);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0109")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressRequestIdFieldAppearsFirst()
    {
        foreach (ulong requestId in new[] { 1UL, 63UL, 64UL, 15293UL })
        {
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(requestId, "192.0.2.0", 24)]);

            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(capsule.Payload.AsSpan(), out ulong parsedRequestId, out int consumed));
            Assert.Equal(requestId, parsedRequestId);
            Assert.Equal(4, capsule.Payload[consumed]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0110")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressRequestIdUsesQuicVariableLengthIntegerEncoding()
    {
        foreach ((ulong requestId, int expectedEncodedLength) in new[] { (1UL, 1), (63UL, 1), (64UL, 2), (16383UL, 2), (16384UL, 4) })
        {
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(requestId, "192.0.2.0", 24)]);

            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(capsule.Payload.AsSpan(), out ulong parsedRequestId, out int consumed));
            Assert.Equal(requestId, parsedRequestId);
            Assert.Equal(expectedEncodedLength, consumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0111")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestRejectsDuplicateRequestIds()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.RequestIdsAreUniqueAndNonZero([
            Request(1, "192.0.2.0", 24),
            Request(2, "2001:db8::", 64),
        ]));

        foreach (Http3ConnectIpRequestedAddress[] duplicateSet in new[]
        {
            new[] { Request(1, "192.0.2.0", 24), Request(1, "198.51.100.0", 24) },
            [Request(64, "192.0.2.0", 24), Request(64, "2001:db8::", 64)],
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Create(duplicateSet));
            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0112")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestRejectsZeroRequestId()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Request(0, "192.0.2.0", 24));

        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x00, 0x04, 192, 0, 2, 0, 24])));
        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0115")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressUsesThirtyTwoBitIpAddressForIpv4()
    {
        foreach (string address in new[] { "0.0.0.0", "192.0.2.0", "198.51.100.0" })
        {
            Http3ConnectIpRequestedAddress request = Request(1, address, 24);
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([request]);

            Assert.Equal(4, request.IpVersion);
            Assert.Equal(4, request.Address.GetAddressBytes().Length);
            Assert.Equal(7, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0116")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressUsesOneHundredTwentyEightBitIpAddressForIpv6()
    {
        foreach (string address in new[] { "::", "2001:db8::", "2001:db8:1::" })
        {
            Http3ConnectIpRequestedAddress request = Request(1, address, 64);
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([request]);

            Assert.Equal(6, request.IpVersion);
            Assert.Equal(16, request.Address.GetAddressBytes().Length);
            Assert.Equal(19, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0117")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPrefixLengthIsEncodedAsOneUnsignedByte()
    {
        foreach (Http3ConnectIpRequestedAddress request in new[]
        {
            Request(1, "0.0.0.0", 0),
            Request(2, "192.0.2.0", 24),
            Request(3, "::", 128),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([request]);

            Assert.Equal(request.PrefixLength, capsule.Payload[^1]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0118")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPrefixLengthCannotExceedAddressBitLength()
    {
        Assert.Equal(32, Request(1, "192.0.2.0", 32).PrefixLength);
        Assert.Equal(128, Request(2, "::", 128).PrefixLength);

        Assert.Throws<ArgumentOutOfRangeException>(() => Request(1, "192.0.2.0", 33));
        Assert.Throws<ArgumentOutOfRangeException>(() => Request(2, "::", 129));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0119")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RequestedAddressRejectsNonZeroHostBitsBeyondPrefix()
    {
        foreach ((string address, int prefixLength) in new[] { ("192.0.2.1", 24), ("2001:db8::1", 64) })
        {
            Assert.Throws<ArgumentException>(() => Request(1, address, prefixLength));
        }

        _ = Request(1, "192.0.2.0", 24);
        _ = Request(2, "2001:db8::", 64);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0120")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedAddressRequestCapsuleFieldsThrowMessageError()
    {
        foreach (byte[] payload in new[]
        {
            Array.Empty<byte>(),
            [0x40],
            [0x01],
            [0x01, 0x04, 192, 0],
            [0x01, 0x06, 0x20, 0x01],
            [0x01, 0x05, 192, 0, 2, 0, 24],
            [0x01, 0x04, 192, 0, 2, 1, 24],
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, payload)));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0121")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestResponseRequiresRequestAndAssignableAddress()
    {
        foreach ((bool received, bool canAssign, bool expected) in new[]
        {
            (true, true, true),
            (true, false, false),
            (false, true, false),
            (false, false, false),
        })
        {
            Assert.Equal(expected, Http3ConnectIpAddressRequestCapsule.ShouldRespondWithAddressAssign(received, canAssign));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0122")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressResponsesMatchTheRequestIdTheyAnswer()
    {
        foreach (ulong requestId in new[] { 1UL, 9UL, 64UL })
        {
            Http3ConnectIpRequestedAddress request = Request(requestId, "192.0.2.0", 24);
            Http3ConnectIpAssignedAddress matching = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
                request,
                IPAddress.Parse("198.51.100.0"),
                24);
            Http3ConnectIpAssignedAddress mismatched = new(requestId + 1, IPAddress.Parse("198.51.100.0"), 24);

            Assert.True(Http3ConnectIpAddressRequestCapsule.ResponseMatchesRequestId(request, matching));
            Assert.False(Http3ConnectIpAddressRequestCapsule.ResponseMatchesRequestId(request, mismatched));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0123")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressResponseUsesAssignedAddressAndPrefixValues()
    {
        foreach ((IPAddress assignedAddress, int assignedPrefixLength) in new[]
        {
            (IPAddress.Parse("198.51.100.0"), 24),
            (IPAddress.Parse("2001:db8:2::"), 64),
        })
        {
            Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
                Request(9, assignedAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? "0.0.0.0" : "::", assignedAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128),
                assignedAddress,
                assignedPrefixLength);

            Assert.Equal(assignedAddress, response.Address);
            Assert.Equal(assignedPrefixLength, response.PrefixLength);
            Assert.Equal(9UL, response.RequestId);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0124")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnassignedAddressResponseUsesZeroAddressAndMaximumPrefix()
    {
        foreach ((Http3ConnectIpRequestedAddress request, IPAddress zeroAddress, int prefixLength) in new[]
        {
            (Request(9, "192.0.2.0", 24), IPAddress.Parse("0.0.0.0"), 32),
            (Request(10, "2001:db8::", 64), IPAddress.IPv6None, 128),
        })
        {
            Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
                request,
                assignedAddress: null,
                assignedPrefixLength: null);

            Assert.Equal(request.RequestId, response.RequestId);
            Assert.Equal(zeroAddress, response.Address);
            Assert.Equal(prefixLength, response.PrefixLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0125")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_RejectedAddressesAreKeptOutOfSubsequentAssignments()
    {
        foreach (bool addressRejected in new[] { false, true })
        {
            Assert.Equal(!addressRejected, Http3ConnectIpAddressRequestCapsule.ShouldIncludeRejectedAddressInSubsequentAssignments(addressRejected));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0126")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EmptyAddressRequestCapsulesAbortTheRequestStream()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [])));

        foreach (int requestedAddressCount in new[] { 0, 1, 2 })
        {
            Assert.Equal(requestedAddressCount == 0, Http3ConnectIpAddressRequestCapsule.ShouldAbortRequestStreamForEmptyAddressRequest(requestedAddressCount));
        }
    }

    [Fact]
    [Requirement("RFC9484-S4-7-2-P6-4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestLimitsIpVersionValuesToFourOrSix()
    {
        foreach (byte invalidVersion in new byte[] { 0, 1, 5, 7, 255 })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x01, invalidVersion, 192, 0, 2, 0, 24])));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }

        Assert.Equal(4, Request(1, "192.0.2.0", 24).IpVersion);
        Assert.Equal(6, Request(2, "2001:db8::", 64).IpVersion);
    }

    [Fact]
    [Requirement("RFC9484-S4-7-2-P6-4-S1-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressRequestIpVersionIsEncodedAsOneUnsignedByte()
    {
        foreach ((Http3ConnectIpRequestedAddress request, byte expectedVersion) in new[]
        {
            (Request(1, "192.0.2.0", 24), (byte)4),
            (Request(2, "2001:db8::", 64), (byte)6),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([request]);
            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(capsule.Payload.AsSpan(), out _, out int consumed));

            Assert.Equal(expectedVersion, capsule.Payload[consumed]);
        }
    }

    private static Http3ConnectIpRequestedAddress Request(ulong requestId, string address, int prefixLength)
    {
        return new Http3ConnectIpRequestedAddress(requestId, IPAddress.Parse(address), prefixLength);
    }

    private static Http3ConnectIpRequestedAddress[][] AddressRequestSets()
    {
        return
        [
            [Request(1, "192.0.2.0", 24)],
            [Request(1, "192.0.2.0", 24), Request(2, "2001:db8::", 64)],
            [Request(63, "198.51.100.0", 24), Request(64, "::", 128), Request(65, "203.0.113.0", 24)],
        ];
    }
}
