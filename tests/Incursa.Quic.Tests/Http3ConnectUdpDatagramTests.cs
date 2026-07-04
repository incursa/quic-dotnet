// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class Http3ConnectUdpDatagramTests
{
    [Fact]
    [Requirement("RFC9298-S4-P1-S3-R01")]
    [Requirement("REQ-QUIC-RFC9298-0086")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_StartsWithContextIdBeforePayload()
    {
        Http3ConnectUdpDatagram datagram = new(2, [0xCA, 0xFE]);

        Assert.Equal([0x02, 0xCA, 0xFE], datagram.Encode());
    }

    [Fact]
    [Requirement("RFC9298-S4-P1-S3-R01")]
    [Requirement("REQ-QUIC-RFC9298-0086")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsMissingContextId()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdpDatagram.Parse([]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0074")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextId_AllowsLargestSixtyTwoBitValue()
    {
        Http3ConnectUdpDatagram datagram = new(Http3ConnectUdpDatagram.MaximumContextId, []);

        Assert.Equal(Http3ConnectUdpDatagram.MaximumContextId, datagram.ContextId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0074")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextId_RejectsValuesBeyondSixtyTwoBits()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => new Http3ConnectUdpDatagram(Http3ConnectUdpDatagram.MaximumContextId + 1, []));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S2-R01")]
    [Requirement("REQ-QUIC-RFC9298-0087")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextId_IsEncodedAsVariableLengthInteger()
    {
        Http3ConnectUdpDatagram datagram = new(64, [0x01]);

        Assert.Equal([0x40, 0x40, 0x01], datagram.Encode());
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S2-R01")]
    [Requirement("REQ-QUIC-RFC9298-0087")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextId_RejectsTruncatedVariableLengthInteger()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdpDatagram.Parse([0x40]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S3-R01")]
    [Requirement("RFC9298-S4-P2-S3-R02")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllocatesDynamicNonZeroContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);
        registry.AllocateProxyContextId(1);

        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(1));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S3-R01")]
    [Requirement("RFC9298-S4-P2-S3-R02")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_RejectsDynamicAllocationOfContextIdZero()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateClientContextId(0));
        Assert.True(registry.IsUsable(Http3ConnectUdpDatagram.UdpPayloadContextId));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0078")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_ClientAllocatesEvenContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(4);

        Assert.True(registry.IsUsable(4));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0078")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_ClientRejectsOddContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateClientContextId(3));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0079")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_ProxyAllocatesOddContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateProxyContextId(3);

        Assert.True(registry.IsUsable(3));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0079")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_ProxyRejectsEvenContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateProxyContextId(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0080")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_ScopesContextIdsPerRequestNamespace()
    {
        Http3ConnectUdpContextIdRegistry firstRequest = new();
        Http3ConnectUdpContextIdRegistry secondRequest = new();

        firstRequest.AllocateClientContextId(2);
        secondRequest.AllocateClientContextId(2);

        Assert.True(firstRequest.IsUsable(2));
        Assert.True(secondRequest.IsUsable(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0080")]
    [Requirement("RFC9298-S4-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_RejectsReallocationInsideOneRequestNamespace()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);

        Assert.Throws<InvalidOperationException>(() => registry.AllocateClientContextId(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0081")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllowsAnyAllocationOrder()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(10);
        registry.AllocateClientContextId(2);

        Assert.Equal([10UL, 2UL], registry.AllocatedContextIds);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0081")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_DoesNotRequireMonotonicAllocationOrder()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Exception? exception = Record.Exception(() =>
        {
            registry.AllocateClientContextId(10);
            registry.AllocateClientContextId(2);
        });

        Assert.Null(exception);
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllowsDistinctContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);
        registry.AllocateClientContextId(4);

        Assert.Equal(2, registry.AllocatedContextIds.Count);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0083")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ContextRegistry_AllocatedContextIdsAreUsableByEitherEndpoint()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);

        Assert.True(registry.IsUsable(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0083")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ContextRegistry_UnknownNonZeroContextIdsAreNotUsable()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Assert.False(registry.IsUsable(2));
    }

    [Theory]
    [Requirement("RFC9298-S4-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void DatagramPolicy_AllowsFutureHeaderOrCapsuleRegistrationMechanisms(bool usesHeaderField, bool usesCapsule)
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField, usesCapsule));
    }

    [Fact]
    [Requirement("RFC9298-S4-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_DoesNotTreatAbsentExtensionSignalAsRegistrationMechanism()
    {
        Assert.False(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0085")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_ContextIdFollowsQuarterStreamIdInHttp3Datagram()
    {
        Http3Datagram httpDatagram = new Http3ConnectUdpDatagram(2, [0xAA]).ToHttp3Datagram(8);

        Assert.Equal([0x02, 0x02, 0xAA], httpDatagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0085")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsHttp3DatagramWithoutContextIdAfterQuarterStreamId()
    {
        Http3Datagram httpDatagram = Http3Datagram.CreateForAssociatedStream(8, []);

        Http3Exception exception = Assert.Throws<Http3Exception>(() => Http3ConnectUdpDatagram.ParseFromHttp3Datagram(httpDatagram));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0088")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_UnknownContextIdCanBeBufferedTemporarily()
    {
        Assert.Equal(Http3ConnectUdpUnknownContextAction.BufferTemporarily, Http3ConnectUdpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0088")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_UnknownContextIdDropsSilentlyWhenBufferUnavailable()
    {
        Assert.Equal(Http3ConnectUdpUnknownContextAction.DropSilently, Http3ConnectUdpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: false));
    }

    [Fact]
    [Requirement("RFC9298-S5-P4-S4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPayload_AllowsEmptyUdpProxyingPayload()
    {
        Http3ConnectUdpDatagram datagram = new(2, []);

        Assert.Empty(datagram.Payload);
    }

    [Fact]
    [Requirement("RFC9298-S5-P4-S4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPayload_RejectsNullPayload()
    {
        Assert.Throws<ArgumentNullException>(() => new Http3ConnectUdpDatagram(2, null!));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0090")]
    [Requirement("REQ-QUIC-RFC9298-0091")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UdpPayload_UsesContextIdZeroAndCarriesUnmodifiedPayload()
    {
        byte[] payload = [0xCA, 0xFE];

        Http3ConnectUdpDatagram datagram = Http3ConnectUdpDatagram.CreateUdpPayload(payload);

        Assert.Equal(0UL, datagram.ContextId);
        Assert.Equal(payload, datagram.Payload);
        Assert.Equal([0x00, 0xCA, 0xFE], datagram.Encode());
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0090")]
    [Requirement("REQ-QUIC-RFC9298-0091")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UdpPayload_NonZeroContextIdIsNotReservedForUdpPackets()
    {
        Http3ConnectUdpDatagram datagram = new(2, [0xCA, 0xFE]);

        Assert.NotEqual(Http3ConnectUdpDatagram.UdpPayloadContextId, datagram.ContextId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0092")]
    [Requirement("REQ-QUIC-RFC9298-0093")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UdpPayload_AllowsMaximumLegalPayloadLength()
    {
        Http3ConnectUdpDatagram datagram = Http3ConnectUdpDatagram.CreateUdpPayload(new byte[Http3ConnectUdpDatagram.MaximumUdpPayloadLength]);

        Assert.Equal(Http3ConnectUdpDatagram.MaximumUdpPayloadLength, datagram.Payload.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0092")]
    [Requirement("REQ-QUIC-RFC9298-0093")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UdpPayload_RejectsOversizedContextIdZeroPayloadsWithDatagramError()
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(
            () => Http3ConnectUdpDatagram.CreateUdpPayload(new byte[Http3ConnectUdpDatagram.MaximumUdpPayloadLength + 1]));

        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0094")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_DiscardsPayloadsLargerThanKnownOutgoingLimit()
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.ShouldDiscardForKnownOutgoingLimit(udpPayloadLength: 1200, outgoingUdpPacketLimit: 1000));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0094")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_ForwardsPayloadsWithinKnownOutgoingLimit()
    {
        Assert.False(Http3ConnectUdpDatagramPolicy.ShouldDiscardForKnownOutgoingLimit(udpPayloadLength: 1000, outgoingUdpPacketLimit: 1200));
        Assert.True(Http3ConnectUdpDatagramPolicy.CanForwardWithoutIpFragmentation(udpPayloadLength: 1000, outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0095")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatagramPolicy_DiscardsDatagramCapsuleWhenCarriedDatagramIsDiscarded()
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.ShouldDiscardDatagramCapsuleWhenDatagramDiscarded(transportedByDatagramCapsule: true));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0095")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DatagramPolicy_DoesNotApplyCapsuleDiscardPolicyToNonCapsuleTransport()
    {
        Assert.False(Http3ConnectUdpDatagramPolicy.ShouldDiscardDatagramCapsuleWhenDatagramDiscarded(transportedByDatagramCapsule: false));
    }
}
