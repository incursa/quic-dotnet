// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpAddressRequestCapsuleTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0100")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_IsSentWhenAssignmentIsExpectedAndNeeded()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.ShouldSendAddressRequest(expectingAddressAssignment: true, needsAddressAssignment: true));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0100")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void AddressRequest_IsNotSentWhenAssignmentIsNotExpectedOrNeeded(bool expectingAddressAssignment, bool needsAddressAssignment)
    {
        Assert.False(Http3ConnectIpAddressRequestCapsule.ShouldSendAddressRequest(expectingAddressAssignment, needsAddressAssignment));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0101")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_CanBeSentUnprompted()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.CanSendUnpromptedAddressAssign);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0101")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_UnpromptedPermissionIsNotDisabled()
    {
        Assert.False(!Http3ConnectIpAddressRequestCapsule.CanSendUnpromptedAddressAssign);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0102")]
    [Requirement("REQ-QUIC-RFC9484-0103")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_UsesTypeTwoWithLengthField()
    {
        Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24)]);
        byte[] encoded = capsule.Encode();

        Assert.Equal(Http3ConnectIpAddressRequestCapsule.CapsuleType, capsule.Type);
        Assert.Equal(0x02, encoded[0]);
        Assert.Equal((byte)capsule.Payload.Length, encoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0102")]
    [Requirement("REQ-QUIC-RFC9484-0103")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_RejectsWrongCapsuleType()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x01, [0x01, 0x04, 192, 0, 2, 0, 24])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0104")]
    [Requirement("REQ-QUIC-RFC9484-0105")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_ContainsOneOrMoreRequestedAddressEntriesAfterLength()
    {
        Http3ConnectIpRequestedAddress[] parsed = Http3ConnectIpAddressRequestCapsule.Parse(
            Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24), Request(2, "2001:db8::", 64)]));

        Assert.Equal(2, parsed.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0104")]
    [Requirement("REQ-QUIC-RFC9484-0105")]
    [Requirement("REQ-QUIC-RFC9484-0126")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_RejectsEmptyRequestedAddressList()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [])));
        Assert.True(Http3ConnectIpAddressRequestCapsule.ShouldAbortRequestStreamForEmptyAddressRequest(0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0106")]
    [Requirement("REQ-QUIC-RFC9484-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_UsesThirtyTwoBitIpv4Address()
    {
        Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24)]);

        Assert.Equal(7, capsule.Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0106")]
    [Requirement("REQ-QUIC-RFC9484-0116")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_UsesOneHundredTwentyEightBitIpv6Address()
    {
        Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(1, "2001:db8::", 64)]);

        Assert.Equal(19, capsule.Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0106")]
    [Requirement("REQ-QUIC-RFC9484-0115")]
    [Requirement("REQ-QUIC-RFC9484-0116")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestedAddress_RejectsTruncatedIpAddressField()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x01, 0x04, 192, 0, 2])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0107")]
    [Requirement("REQ-QUIC-RFC9484-0117")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_EncodesPrefixLengthAsUnsignedByte()
    {
        Http3ConnectIpRequestedAddress parsed = Assert.Single(Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24)])));

        Assert.Equal(24, parsed.PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0107")]
    [Requirement("REQ-QUIC-RFC9484-0117")]
    [Requirement("REQ-QUIC-RFC9484-0118")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestedAddress_RejectsPrefixLengthBeyondAddressLength()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x01, 0x04, 192, 0, 2, 0, 33])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0108")]
    [Requirement("REQ-QUIC-RFC9484-0113")]
    [Requirement("RFC9484-S4-7-2-P6-4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_EncodesIpVersionAsUnsignedByteFourOrSix()
    {
        Assert.Equal(4, Request(1, "192.0.2.0", 24).IpVersion);
        Assert.Equal(6, Request(2, "2001:db8::", 64).IpVersion);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0108")]
    [Requirement("REQ-QUIC-RFC9484-0113")]
    [Requirement("RFC9484-S4-7-2-P6-4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestedAddress_RejectsUnsupportedIpVersion()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x01, 0x05, 192, 0, 2, 0, 24])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0109")]
    [Requirement("REQ-QUIC-RFC9484-0110")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_EncodesRequestIdFirstAsVariableLengthInteger()
    {
        Http3Capsule capsule = Http3ConnectIpAddressRequestCapsule.Create([Request(64, "192.0.2.0", 24)]);

        Assert.Equal(0x40, capsule.Payload[0]);
        Assert.Equal(0x40, capsule.Payload[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0109")]
    [Requirement("REQ-QUIC-RFC9484-0110")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestedAddress_RejectsTruncatedRequestIdVarint()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x40])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0111")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_AllowsUniqueRequestIds()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.RequestIdsAreUniqueAndNonZero([Request(1, "192.0.2.0", 24), Request(2, "2001:db8::", 64)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0111")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_RejectsReusedRequestIds()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24), Request(1, "2001:db8::", 64)]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0112")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_AcceptsNonZeroRequestId()
    {
        Assert.Equal(1UL, Request(1, "192.0.2.0", 24).RequestId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0112")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_RejectsZeroRequestId()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Request(0, "192.0.2.0", 24));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0118")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_AllowsPrefixLengthEqualToAddressLength()
    {
        Assert.Equal(32, Request(1, "192.0.2.1", 32).PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0119")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequestedAddress_AcceptsZeroUnusedAddressBits()
    {
        Assert.Equal(24, Request(1, "192.0.2.0", 24).PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0119")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RequestedAddress_RejectsNonZeroUnusedAddressBits()
    {
        Assert.Throws<ArgumentException>(() => Request(1, "192.0.2.1", 24));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0120")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_ParsesWellFormedCapsuleFields()
    {
        Http3ConnectIpRequestedAddress parsed = Assert.Single(Http3ConnectIpAddressRequestCapsule.Parse(Http3ConnectIpAddressRequestCapsule.Create([Request(1, "192.0.2.0", 24)])));

        Assert.Equal(IPAddress.Parse("192.0.2.0"), parsed.Address);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0120")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_MalformedCapsuleFieldsThrowMessageError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressRequestCapsule.Parse(new Http3Capsule(0x02, [0x01, 0x04])));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0121")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_RespondsWithAddressAssignWhenAddressCanBeAssigned()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.ShouldRespondWithAddressAssign(addressRequestReceived: true, canAssignAtLeastOneAddress: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0121")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_DoesNotRespondWithoutAddressRequest()
    {
        Assert.False(Http3ConnectIpAddressRequestCapsule.ShouldRespondWithAddressAssign(addressRequestReceived: false, canAssignAtLeastOneAddress: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0122")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_AssignedResponseMatchesRequestId()
    {
        Http3ConnectIpRequestedAddress request = Request(9, "192.0.2.0", 24);
        Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(request, IPAddress.Parse("192.0.2.0"), 24);

        Assert.True(Http3ConnectIpAddressRequestCapsule.ResponseMatchesRequestId(request, response));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0122")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_DetectsMismatchedResponseRequestId()
    {
        Http3ConnectIpRequestedAddress request = Request(9, "192.0.2.0", 24);
        Http3ConnectIpAssignedAddress response = new(10, IPAddress.Parse("192.0.2.0"), 24);

        Assert.False(Http3ConnectIpAddressRequestCapsule.ResponseMatchesRequestId(request, response));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0123")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_AssignedResponseUsesAssignedValues()
    {
        Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
            Request(9, "0.0.0.0", 32),
            IPAddress.Parse("192.0.2.0"),
            24);

        Assert.Equal(IPAddress.Parse("192.0.2.0"), response.Address);
        Assert.Equal(24, response.PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0123")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_AssignedResponseDoesNotUseRequestedPlaceholderWhenAssigned()
    {
        Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
            Request(9, "0.0.0.0", 32),
            IPAddress.Parse("192.0.2.0"),
            24);

        Assert.NotEqual(IPAddress.Parse("0.0.0.0"), response.Address);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0124")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("0.0.0.0", 32)]
    [InlineData("::", 128)]
    public void AddressRequest_UnassignedResponseUsesZeroAddressAndMaxPrefix(string requestedAddress, int expectedPrefix)
    {
        Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
            Request(9, requestedAddress, expectedPrefix),
            assignedAddress: null,
            assignedPrefixLength: null);

        Assert.Equal(expectedPrefix, response.PrefixLength);
        Assert.True(response.Address.Equals(IPAddress.Parse(requestedAddress)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0124")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_UnassignedResponseDoesNotUseRequestedNonZeroPrefix()
    {
        Http3ConnectIpAssignedAddress response = Http3ConnectIpAddressRequestCapsule.CreateAssignedAddressResponse(
            Request(9, "192.0.2.0", 24),
            assignedAddress: null,
            assignedPrefixLength: null);

        Assert.Equal(IPAddress.Parse("0.0.0.0"), response.Address);
        Assert.Equal(32, response.PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0125")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_RejectionsAreKeptOutOfSubsequentAssignments()
    {
        Assert.False(Http3ConnectIpAddressRequestCapsule.ShouldIncludeRejectedAddressInSubsequentAssignments(addressRejected: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0125")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressRequest_NonRejectedAddressesCanRemainInSubsequentAssignments()
    {
        Assert.True(Http3ConnectIpAddressRequestCapsule.ShouldIncludeRejectedAddressInSubsequentAssignments(addressRejected: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0126")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressRequest_NonEmptyRequestDoesNotAbortRequestStream()
    {
        Assert.False(Http3ConnectIpAddressRequestCapsule.ShouldAbortRequestStreamForEmptyAddressRequest(1));
    }

    private static Http3ConnectIpRequestedAddress Request(ulong requestId, string address, int prefixLength)
    {
        return new Http3ConnectIpRequestedAddress(requestId, IPAddress.Parse(address), prefixLength);
    }
}
