// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpAddressAssignCapsuleTests
{
    [Fact]
    [Requirement("RFC9484-S4-7-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_AllowsAnyNonNegativeNumberOfNewCapsules()
    {
        Assert.True(Http3ConnectIpAddressAssignCapsule.CanSendNewCapsuleCount(0));
        Assert.True(Http3ConnectIpAddressAssignCapsule.CanSendNewCapsuleCount(3));
    }

    [Fact]
    [Requirement("RFC9484-S4-7-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_RejectsImpossibleNegativeCapsuleCount()
    {
        Assert.False(Http3ConnectIpAddressAssignCapsule.CanSendNewCapsuleCount(-1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0081")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_ContainsFullAssignedPrefixList()
    {
        Http3ConnectIpAssignedAddress[] current = [V4("192.0.2.0", 24), V6("2001:db8::", 64)];
        Http3ConnectIpAssignedAddress[] parsed = Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create(current));

        Assert.True(Http3ConnectIpAddressAssignCapsule.ContainsFullAssignedPrefixList(current, parsed));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0081")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_DetectsMissingAssignedPrefixFromList()
    {
        Http3ConnectIpAssignedAddress[] current = [V4("192.0.2.0", 24), V6("2001:db8::", 64)];
        Http3ConnectIpAssignedAddress[] incomplete = [V4("192.0.2.0", 24)];

        Assert.False(Http3ConnectIpAddressAssignCapsule.ContainsFullAssignedPrefixList(current, incomplete));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0082")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_UsesTypeOneWithLengthAndPayload()
    {
        Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)]);
        byte[] encoded = capsule.Encode();

        Assert.Equal(Http3ConnectIpAddressAssignCapsule.CapsuleType, capsule.Type);
        Assert.Equal(0x01, encoded[0]);
        Assert.Equal((byte)capsule.Payload.Length, encoded[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0082")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_RejectsWrongCapsuleType()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x02, [])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0083")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_AllowsZeroOrMoreAssignedAddresses()
    {
        Assert.Empty(Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([])));
        Assert.Equal(2, Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24), V6("2001:db8::", 64)])).Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0083")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_RejectsTruncatedAssignedAddressSequence()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x04, 192, 0, 2])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0084")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_EncodesRequestIdIpVersionIpAddressAndPrefixLengthInOrder()
    {
        Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)]);

        Assert.Equal([0x00, 0x04, 192, 0, 2, 0, 24], capsule.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0084")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsTruncatedFieldLayout()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x04, 192, 0, 2, 0])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_EncodesRequestIdAsVariableLengthInteger()
    {
        Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(64, IPAddress.Parse("192.0.2.0"), 24)]);

        Assert.Equal(0x40, capsule.Payload[0]);
        Assert.Equal(0x40, capsule.Payload[1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0085")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsTruncatedRequestIdVariableLengthInteger()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x40])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0086")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_UsesRequestIdForAddressRequestResponses()
    {
        Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(
            Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(7, IPAddress.Parse("192.0.2.0"), 24)])));

        Assert.Equal(7UL, parsed.RequestId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0086")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_UsesZeroRequestIdForUnpromptedAssignments()
    {
        Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)])));

        Assert.Equal(0UL, parsed.RequestId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0087")]
    [Requirement("REQ-QUIC-RFC9484-0088")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_EncodesIpVersionAsUnsignedByteIdentifyingAddressVersion()
    {
        Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)])));

        Assert.Equal(4, parsed.IpVersion);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0087")]
    [Requirement("REQ-QUIC-RFC9484-0088")]
    [Requirement("REQ-QUIC-RFC9484-0089")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsUnsupportedIpVersionByte()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x05, 192, 0, 2, 0, 24])));
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0089")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("192.0.2.0", 4)]
    [InlineData("2001:db8::", 6)]
    public void AssignedAddress_RestrictsIpVersionToFourOrSix(string address, int expectedVersion)
    {
        Http3ConnectIpAssignedAddress assigned = new(0, IPAddress.Parse(address), expectedVersion == 4 ? 24 : 64);

        Assert.Equal(expectedVersion, assigned.IpVersion);
    }

    [Theory]
    [Requirement("REQ-QUIC-RFC9484-0090")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData("192.0.2.0", 4)]
    [InlineData("2001:db8::", 16)]
    public void AssignedAddress_AddressLengthFollowsIpVersion(string address, int expectedLength)
    {
        Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), expectedLength == 4 ? 24 : 64)]);

        Assert.Equal(expectedLength + 3, capsule.Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0090")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsAddressLengthThatDoesNotMatchIpVersion()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x06, 192, 0, 2, 0, 24])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0091")]
    [Requirement("REQ-QUIC-RFC9484-0092")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_EncodesPrefixLengthAsUnsignedByteWithPrefixMeaning()
    {
        Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)])));

        Assert.Equal(24, parsed.PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0091")]
    [Requirement("REQ-QUIC-RFC9484-0092")]
    [Requirement("REQ-QUIC-RFC9484-0093")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsPrefixLengthBeyondAddressLength()
    {
        Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x04, 192, 0, 2, 0, 33])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0093")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_AllowsPrefixLengthEqualToAddressLength()
    {
        Assert.Equal(32, V4("192.0.2.1", 32).PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0094")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_FullLengthPrefixAllowsSingleSourceAddress()
    {
        Http3ConnectIpAssignedAddress assigned = V4("192.0.2.1", 32);

        Assert.True(assigned.AllowsSingleSourceAddress);
        Assert.True(assigned.AllowsSourceAddress(IPAddress.Parse("192.0.2.1")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0094")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_FullLengthPrefixDoesNotAllowDifferentSourceAddress()
    {
        Http3ConnectIpAssignedAddress assigned = V4("192.0.2.1", 32);

        Assert.False(assigned.AllowsSourceAddress(IPAddress.Parse("192.0.2.2")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0095")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_PrefixLengthAllowsAnySourceInsidePrefix()
    {
        Http3ConnectIpAssignedAddress assigned = V4("192.0.2.0", 24);

        Assert.True(assigned.AllowsSourceAddress(IPAddress.Parse("192.0.2.99")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0095")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_PrefixLengthRejectsSourceOutsidePrefix()
    {
        Http3ConnectIpAssignedAddress assigned = V4("192.0.2.0", 24);

        Assert.False(assigned.AllowsSourceAddress(IPAddress.Parse("192.0.3.1")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0096")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AssignedAddress_AcceptsZeroUnusedAddressBits()
    {
        Assert.Equal(24, V4("192.0.2.0", 24).PrefixLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0096")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AssignedAddress_RejectsNonZeroUnusedAddressBits()
    {
        Assert.Throws<ArgumentException>(() => V4("192.0.2.1", 24));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0097")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_ParsesWellFormedCapsuleFields()
    {
        Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([V4("192.0.2.0", 24)])));

        Assert.Equal(IPAddress.Parse("192.0.2.0"), parsed.Address);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0097")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_MalformedCapsuleFieldsThrowMessageError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, 0x04])));

        Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0098")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_OmittedPreviousAddressIsRemoved()
    {
        Http3ConnectIpAssignedAddress retained = V4("192.0.2.0", 24);
        Http3ConnectIpAssignedAddress removed = V6("2001:db8::", 64);

        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList([retained, removed], [retained]);

        Assert.Single(updated);
        Assert.Equal(retained.Address, updated[0].Address);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0098")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_PresentPreviousAddressIsNotRemoved()
    {
        Http3ConnectIpAssignedAddress retained = V4("192.0.2.0", 24);

        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList([retained], [retained]);

        Assert.Single(updated);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0099")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AddressAssign_EmptyCapsuleRemovesAllAddresses()
    {
        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList([V4("192.0.2.0", 24)], []);

        Assert.Empty(updated);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0099")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AddressAssign_NonEmptyCapsuleDoesNotRemoveAllAddresses()
    {
        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList([], [V4("192.0.2.0", 24)]);

        Assert.NotEmpty(updated);
    }

    private static Http3ConnectIpAssignedAddress V4(string address, int prefixLength)
    {
        return new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), prefixLength);
    }

    private static Http3ConnectIpAssignedAddress V6(string address, int prefixLength)
    {
        return new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), prefixLength);
    }
}
