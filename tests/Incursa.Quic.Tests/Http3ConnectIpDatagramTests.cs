// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectIpDatagramTests
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0150")]
    [Requirement("REQ-QUIC-RFC9484-0160")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_StartsWithContextIdBeforePayload()
    {
        Http3ConnectIpDatagram datagram = new(2, [0xCA, 0xFE]);

        Assert.Equal([0x02, 0xCA, 0xFE], datagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0150")]
    [Requirement("REQ-QUIC-RFC9484-0160")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsMissingContextId()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpDatagram.Parse([]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0151")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextId_AllowsLargestSixtyTwoBitValue()
    {
        Http3ConnectIpDatagram datagram = new(Http3ConnectIpDatagram.MaximumContextId, []);

        Assert.Equal(Http3ConnectIpDatagram.MaximumContextId, datagram.ContextId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0151")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextId_RejectsValuesBeyondSixtyTwoBits()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => new Http3ConnectIpDatagram(Http3ConnectIpDatagram.MaximumContextId + 1, []));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0152")]
    [Requirement("REQ-QUIC-RFC9484-0161")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextId_IsEncodedAsVariableLengthInteger()
    {
        Http3ConnectIpDatagram datagram = new(64, [0x01]);

        Assert.Equal([0x40, 0x40, 0x01], datagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0152")]
    [Requirement("REQ-QUIC-RFC9484-0161")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextId_RejectsTruncatedVariableLengthInteger()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpDatagram.Parse([0x40]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0153")]
    [Requirement("REQ-QUIC-RFC9484-0154")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllocatesDynamicNonZeroContextIds()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(9);

        Assert.True(registry.IsUsable(9));
        Assert.True(registry.IsUsable(Http3ConnectIpDatagram.IpPayloadContextId));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0153")]
    [Requirement("REQ-QUIC-RFC9484-0154")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_RejectsDynamicAllocationOfContextIdZero()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateContextId(0));
        Assert.True(registry.IsUsable(Http3ConnectIpDatagram.IpPayloadContextId));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0155")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllowsAnyAllocationOrder()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(10);
        registry.AllocateContextId(2);

        Assert.Equal([10UL, 2UL], registry.AllocatedContextIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0155")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_DoesNotRequireMonotonicAllocationOrder()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        Exception? exception = Record.Exception(() =>
        {
            registry.AllocateContextId(10);
            registry.AllocateContextId(2);
        });

        Assert.Null(exception);
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S6-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllowsDistinctContextIds()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(2);
        registry.AllocateContextId(4);

        Assert.Equal(2, registry.AllocatedContextIds.Count);
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S6-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_RejectsReallocationInsideOneRequestNamespace()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(2);

        Assert.Throws<InvalidOperationException>(() => registry.AllocateContextId(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0157")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllocatedContextIdsAreUsableByEitherEndpoint()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(2);

        Assert.True(registry.IsUsable(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0157")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_UnknownNonZeroContextIdsAreNotUsable()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        Assert.False(registry.IsUsable(2));
    }

    [Theory]
    [Requirement("RFC9484-S5-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DatagramPolicy_AllowsFutureHeaderOrCapsuleRegistrationMechanisms(bool usesHeaderField, bool usesCapsule)
    {
        Assert.True(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField, usesCapsule));
    }

    [Fact]
    [Requirement("RFC9484-S5-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_DoesNotTreatAbsentExtensionSignalAsRegistrationMechanism()
    {
        Assert.False(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0159")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_ContextIdFollowsQuarterStreamIdInHttp3Datagram()
    {
        Http3Datagram httpDatagram = new Http3ConnectIpDatagram(2, [0xAA]).ToHttp3Datagram(8);

        Assert.Equal([0x02, 0x02, 0xAA], httpDatagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0159")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsHttp3DatagramWithoutContextIdAfterQuarterStreamId()
    {
        Http3Datagram httpDatagram = Http3Datagram.CreateForAssociatedStream(8, []);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpDatagram.ParseFromHttp3Datagram(httpDatagram));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0162")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_UnknownContextIdCanBeBufferedTemporarily()
    {
        Assert.Equal(Http3ConnectIpUnknownContextAction.BufferTemporarily, Http3ConnectIpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0162")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_UnknownContextIdDropsSilentlyWhenBufferUnavailable()
    {
        Assert.Equal(Http3ConnectIpUnknownContextAction.DropSilently, Http3ConnectIpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0163")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_ContextIdDefinesPayloadSemantics()
    {
        Assert.True(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(Http3ConnectIpDatagram.IpPayloadContextId, contextIdRegistered: false));
        Assert.True(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(2, contextIdRegistered: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0163")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_UnknownNonZeroContextHasNoPayloadSemantics()
    {
        Assert.False(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(2, contextIdRegistered: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0164")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_AllowsEmptyExtensionPayload()
    {
        Http3ConnectIpDatagram datagram = new(2, []);

        Assert.Empty(datagram.Payload);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0164")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsNullPayload()
    {
        Assert.Throws<ArgumentNullException>(() => new Http3ConnectIpDatagram(2, null!));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0165")]
    [Requirement("REQ-QUIC-RFC9484-0166")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpPacketPayload_UsesContextIdZeroAndCarriesFullIpv4Packet()
    {
        byte[] packet = CreateIpv4Packet();

        Http3ConnectIpDatagram datagram = Http3ConnectIpDatagram.CreateIpPacketPayload(packet);

        Assert.Equal(0UL, datagram.ContextId);
        Assert.Equal(packet, datagram.Payload);
        Assert.Equal([0x00, .. packet], datagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0165")]
    [Requirement("REQ-QUIC-RFC9484-0166")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpPacketPayload_RejectsNonIpPacketAtContextIdZero()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectIpDatagram.CreateIpPacketPayload([0x10, 0x00]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0166")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void IpPacketPayload_AcceptsFullIpv6Packet()
    {
        Assert.True(Http3ConnectIpDatagram.IsFullIpPacket(CreateIpv6Packet(payloadLength: 2)));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0166")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void IpPacketPayload_RejectsTruncatedIpv6Packet()
    {
        byte[] packet = CreateIpv6Packet(payloadLength: 2);

        Assert.False(Http3ConnectIpDatagram.IsFullIpPacket(packet[..^1]));
    }

    [Fact]
    [Requirement("RFC9484-S7-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_AllowsOptimisticIpPacketsOverHttp2OrHttp3()
    {
        Assert.True(Http3ConnectIpDatagramPolicy.CanClientOptimisticallySendIpPackets(usingHttp2: true, usingHttp3: false));
        Assert.True(Http3ConnectIpDatagramPolicy.CanClientOptimisticallySendIpPackets(usingHttp2: false, usingHttp3: true));
    }

    [Fact]
    [Requirement("RFC9484-S7-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_DoesNotAllowOptimisticIpPacketsOutsideHttp2OrHttp3()
    {
        Assert.False(Http3ConnectIpDatagramPolicy.CanClientOptimisticallySendIpPackets(usingHttp2: false, usingHttp3: false));
    }

    private static byte[] CreateIpv4Packet()
    {
        return [0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 64, 6, 0x00, 0x00, 192, 0, 2, 1, 192, 0, 2, 2];
    }

    private static byte[] CreateIpv6Packet(int payloadLength)
    {
        byte[] packet = new byte[40 + payloadLength];
        packet[0] = 0x60;
        packet[4] = (byte)(payloadLength >> 8);
        packet[5] = (byte)payloadLength;
        packet[6] = 6;
        packet[7] = 64;
        return packet;
    }
}
