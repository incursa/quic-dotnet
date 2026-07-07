// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_AddressAssignFuzzClosure
{
    [Fact]
    [Requirement("RFC9484-S4-7-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignAllowsAnyNonNegativeNumberOfCapsules()
    {
        foreach (int capsuleCount in new[] { 0, 1, 2, 8, 64 })
        {
            Assert.True(Http3ConnectIpAddressAssignCapsule.CanSendNewCapsuleCount(capsuleCount));
        }

        Assert.False(Http3ConnectIpAddressAssignCapsule.CanSendNewCapsuleCount(-1));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0081")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignContainsCompleteAssignedPrefixList()
    {
        foreach (Http3ConnectIpAssignedAddress[] assignments in AssignmentSets())
        {
            Http3ConnectIpAssignedAddress[] parsed = Http3ConnectIpAddressAssignCapsule.Parse(
                Http3ConnectIpAddressAssignCapsule.Create(assignments));

            Assert.True(Http3ConnectIpAddressAssignCapsule.ContainsFullAssignedPrefixList(assignments, parsed));
            if (assignments.Length > 0)
            {
                Assert.False(Http3ConnectIpAddressAssignCapsule.ContainsFullAssignedPrefixList(assignments, parsed.Skip(1).ToArray()));
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0082")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignCapsuleUsesTypeOneLengthAndPayloadFields()
    {
        foreach (Http3ConnectIpAssignedAddress[] assignments in AssignmentSets())
        {
            Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create(assignments);
            byte[] encoded = capsule.Encode();

            Assert.Equal(0x01UL, capsule.Type);
            Assert.Equal(0x01, encoded[0]);
            Assert.Equal(capsule.Payload.Length, encoded[1]);
            Assert.Equal(capsule.Payload, encoded.AsSpan(2).ToArray());
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0083")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignContainsZeroOrMoreAssignedAddresses()
    {
        foreach (Http3ConnectIpAssignedAddress[] assignments in AssignmentSets())
        {
            Http3ConnectIpAssignedAddress[] parsed = Http3ConnectIpAddressAssignCapsule.Parse(
                Http3ConnectIpAddressAssignCapsule.Create(assignments));

            Assert.Equal(assignments.Length, parsed.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0084")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressLayoutEncodesRequestIdIpVersionAddressAndPrefixLength()
    {
        Http3Capsule ipv4 = Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(7, IPAddress.Parse("192.0.2.0"), 24)]);
        Http3Capsule ipv6 = Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(7, IPAddress.Parse("2001:db8::"), 64)]);

        Assert.Equal([0x07, 0x04, 192, 0, 2, 0, 24], ipv4.Payload);
        Assert.Equal(0x07, ipv6.Payload[0]);
        Assert.Equal(0x06, ipv6.Payload[1]);
        Assert.Equal(64, ipv6.Payload[^1]);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0085")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressRequestIdUsesVariableLengthIntegerEncoding()
    {
        foreach ((ulong requestId, byte firstByte, int encodedLength) in new[]
        {
            (0UL, (byte)0x00, 1),
            (63UL, (byte)0x3F, 1),
            (64UL, (byte)0x40, 2),
            (16383UL, (byte)0x7F, 2),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(requestId, IPAddress.Parse("192.0.2.0"), 24)]);
            Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(capsule));

            Assert.Equal(firstByte, capsule.Payload[0]);
            Assert.Equal(requestId, parsed.RequestId);
            Assert.Equal(encodedLength + 6, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0086")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressRequestIdCarriesResponseIdOrZero()
    {
        foreach (ulong requestId in new[] { 0UL, 1UL, 7UL, 64UL })
        {
            Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(
                Http3ConnectIpAddressAssignCapsule.Create([new Http3ConnectIpAssignedAddress(requestId, IPAddress.Parse("192.0.2.0"), 24)])));

            Assert.Equal(requestId, parsed.RequestId);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0087")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressIpVersionIsEncodedAsUnsignedEightBitInteger()
    {
        foreach ((Http3ConnectIpAssignedAddress address, byte expectedVersion) in new[]
        {
            (V4("192.0.2.0", 24), (byte)4),
            (V6("2001:db8::", 64), (byte)6),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([address]);

            Assert.Equal(expectedVersion, capsule.Payload[1]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0088")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressIpVersionIdentifiesAssignmentAddressVersion()
    {
        foreach ((Http3ConnectIpAssignedAddress address, int expectedVersion) in new[]
        {
            (V4("192.0.2.0", 24), 4),
            (V6("2001:db8::", 64), 6),
        })
        {
            Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(
                Http3ConnectIpAddressAssignCapsule.Create([address])));

            Assert.Equal(expectedVersion, parsed.IpVersion);
            Assert.Equal(expectedVersion, Http3ConnectIpScopePolicy.GetIpVersion(parsed.Address));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0089")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressRejectsIpVersionsOtherThanFourOrSix()
    {
        foreach (byte invalidVersion in new byte[] { 0, 1, 5, 7, 255 })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, [0x00, invalidVersion, 192, 0, 2, 0, 24])));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0090")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressLengthFollowsIpVersion()
    {
        foreach ((Http3ConnectIpAssignedAddress address, int expectedAddressLength) in new[]
        {
            (V4("192.0.2.0", 24), 4),
            (V6("2001:db8::", 64), 16),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([address]);
            Http3ConnectIpAssignedAddress parsed = Assert.Single(Http3ConnectIpAddressAssignCapsule.Parse(capsule));

            Assert.Equal(expectedAddressLength, parsed.Address.GetAddressBytes().Length);
            Assert.Equal(expectedAddressLength + 3, capsule.Payload.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0091")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressPrefixLengthIsEncodedAsUnsignedEightBitInteger()
    {
        foreach ((Http3ConnectIpAssignedAddress address, byte expectedPrefixLength) in new[]
        {
            (V4("192.0.2.0", 24), (byte)24),
            (V4("192.0.2.1", 32), (byte)32),
            (V6("2001:db8::", 64), (byte)64),
            (V6("2001:db8::1", 128), (byte)128),
        })
        {
            Http3Capsule capsule = Http3ConnectIpAddressAssignCapsule.Create([address]);

            Assert.Equal(expectedPrefixLength, capsule.Payload[^1]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0092")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressPrefixLengthDefinesAssignedPrefixBits()
    {
        Http3ConnectIpAssignedAddress ipv4 = V4("192.0.2.0", 24);
        Http3ConnectIpAssignedAddress ipv6 = V6("2001:db8::", 64);

        Assert.True(ipv4.AllowsSourceAddress(IPAddress.Parse("192.0.2.200")));
        Assert.False(ipv4.AllowsSourceAddress(IPAddress.Parse("192.0.3.1")));
        Assert.True(ipv6.AllowsSourceAddress(IPAddress.Parse("2001:db8::1234")));
        Assert.False(ipv6.AllowsSourceAddress(IPAddress.Parse("2001:db9::1")));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0093")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressPrefixLengthCannotExceedAddressBitLength()
    {
        foreach ((string address, int validPrefix, int invalidPrefix) in new[]
        {
            ("192.0.2.0", 32, 33),
            ("2001:db8::", 128, 129),
        })
        {
            Assert.Equal(validPrefix, new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), validPrefix).PrefixLength);
            Assert.Throws<ArgumentOutOfRangeException>(() => new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), invalidPrefix));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0094")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FullLengthAssignedPrefixAllowsSingleSourceAddress()
    {
        foreach (Http3ConnectIpAssignedAddress address in new[]
        {
            V4("192.0.2.1", 32),
            V6("2001:db8::1", 128),
        })
        {
            Assert.True(address.AllowsSingleSourceAddress);
            Assert.True(address.AllowsSourceAddress(address.Address));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0095")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ShorterAssignedPrefixAllowsAnySourceAddressInsidePrefix()
    {
        foreach ((Http3ConnectIpAssignedAddress prefix, IPAddress inside, IPAddress outside) in new[]
        {
            (V4("192.0.2.0", 24), IPAddress.Parse("192.0.2.123"), IPAddress.Parse("192.0.3.1")),
            (V6("2001:db8::", 64), IPAddress.Parse("2001:db8::abcd"), IPAddress.Parse("2001:db9::1")),
        })
        {
            Assert.False(prefix.AllowsSingleSourceAddress);
            Assert.True(prefix.AllowsSourceAddress(inside));
            Assert.False(prefix.AllowsSourceAddress(outside));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0096")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AssignedAddressRequiresZeroHostBitsOutsidePrefix()
    {
        foreach ((string valid, string invalid, int prefixLength) in new[]
        {
            ("192.0.2.0", "192.0.2.1", 24),
            ("2001:db8::", "2001:db8::1", 64),
        })
        {
            Assert.Equal(prefixLength, new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(valid), prefixLength).PrefixLength);
            Assert.Throws<ArgumentException>(() => new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(invalid), prefixLength));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0097")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_MalformedAddressAssignCapsuleFieldsThrowMessageError()
    {
        foreach (byte[] payload in new byte[][]
        {
            [0x40],
            [0x00],
            [0x00, 0x04, 192, 0, 2],
            [0x00, 0x04, 192, 0, 2, 0, 33],
            [0x00, 0x06, 0x20, 0x01],
            [0x00, 0x05, 192, 0, 2, 0, 24],
        })
        {
            Http3Exception exception = Assert.Throws<Http3Exception>(
                () => Http3ConnectIpAddressAssignCapsule.Parse(new Http3Capsule(0x01, payload)));

            Assert.Equal(Http3ErrorCode.MessageError, exception.ErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0098")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AddressAssignMissingPreviousAddressRemovesThatAddress()
    {
        Http3ConnectIpAssignedAddress retained = V4("192.0.2.0", 24);
        Http3ConnectIpAssignedAddress removed = V6("2001:db8::", 64);

        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList([retained, removed], [retained]);

        Assert.Single(updated);
        Assert.Equal(retained.Address, updated[0].Address);
        Assert.DoesNotContain(updated, assignment => assignment.Address.Equals(removed.Address));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0099")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EmptyAddressAssignCapsuleRemovesAllAddresses()
    {
        Http3ConnectIpAssignedAddress[] previous =
        [
            V4("192.0.2.0", 24),
            V6("2001:db8::", 64),
        ];

        Http3ConnectIpAssignedAddress[] updated = Http3ConnectIpAddressAssignCapsule.ApplyCompleteAssignmentList(previous, []);
        Http3ConnectIpAssignedAddress[] parsedEmpty = Http3ConnectIpAddressAssignCapsule.Parse(Http3ConnectIpAddressAssignCapsule.Create([]));

        Assert.Empty(updated);
        Assert.Empty(parsedEmpty);
    }

    private static Http3ConnectIpAssignedAddress V4(string address, int prefixLength)
    {
        return new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), prefixLength);
    }

    private static Http3ConnectIpAssignedAddress V6(string address, int prefixLength)
    {
        return new Http3ConnectIpAssignedAddress(0, IPAddress.Parse(address), prefixLength);
    }

    private static Http3ConnectIpAssignedAddress[][] AssignmentSets()
    {
        return
        [
            [],
            [V4("192.0.2.0", 24)],
            [V4("192.0.2.0", 24), V6("2001:db8::", 64)],
            [new Http3ConnectIpAssignedAddress(7, IPAddress.Parse("198.51.100.0"), 24), new Http3ConnectIpAssignedAddress(64, IPAddress.Parse("2001:db8:1::"), 64)],
        ];
    }
}
