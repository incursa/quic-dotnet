// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9298_DatagramFuzzClosure
{
    [Fact]
    [Requirement("RFC9298-S4-P1-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_HttpDatagramsStartWithContextId()
    {
        foreach ((ulong contextId, byte[] payload, byte[] expectedPrefix) in new[]
        {
            (2UL, new byte[] { 0xCA, 0xFE }, new byte[] { 0x02 }),
            (64UL, new byte[] { 0xAA }, new byte[] { 0x40, 0x40 }),
        })
        {
            byte[] encoded = new Http3ConnectUdpDatagram(contextId, payload).Encode();

            Assert.True(encoded.AsSpan(0, expectedPrefix.Length).SequenceEqual(expectedPrefix));
            Assert.Equal(payload, Http3ConnectUdpDatagram.Parse(encoded).Payload);
        }

        AssertDatagramError(() => Http3ConnectUdpDatagram.Parse([]));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsAreSixtyTwoBitIntegers()
    {
        foreach (ulong contextId in new[] { 0UL, 1UL, 63UL, 64UL, Http3ConnectUdpDatagram.MaximumContextId })
        {
            Assert.Equal(contextId, new Http3ConnectUdpDatagram(contextId, []).ContextId);
        }

        AssertDatagramError(() => new Http3ConnectUdpDatagram(Http3ConnectUdpDatagram.MaximumContextId + 1, []));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsUseQuicVariableLengthIntegerEncoding()
    {
        foreach ((ulong contextId, byte[] expectedPrefix) in new[]
        {
            (1UL, new byte[] { 0x01 }),
            (63UL, new byte[] { 0x3F }),
            (64UL, new byte[] { 0x40, 0x40 }),
        })
        {
            byte[] encoded = new Http3ConnectUdpDatagram(contextId, [0xAA]).Encode();

            Assert.True(encoded.AsSpan(0, expectedPrefix.Length).SequenceEqual(expectedPrefix));
            Assert.Equal(contextId, Http3ConnectUdpDatagram.Parse(encoded).ContextId);
        }

        AssertDatagramError(() => Http3ConnectUdpDatagram.Parse([0x40]));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonZeroContextIdsMustBeDynamicallyAllocated()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        Assert.False(registry.IsUsable(2));
        registry.AllocateClientContextId(2);
        registry.AllocateProxyContextId(1);

        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(1));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdZeroIsReservedForUdpPayloads()
    {
        Http3ConnectUdpContextIdRegistry registry = new();
        Http3ConnectUdpDatagram datagram = Http3ConnectUdpDatagram.CreateUdpPayload([0xCA]);

        Assert.Equal(0UL, datagram.ContextId);
        Assert.True(registry.IsUsable(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateClientContextId(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateProxyContextId(0));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientAllocatesNonZeroEvenContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);
        registry.AllocateClientContextId(64);

        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(64));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateClientContextId(3));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S4-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyAllocatesOddContextIds()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateProxyContextId(1);
        registry.AllocateProxyContextId(63);

        Assert.True(registry.IsUsable(1));
        Assert.True(registry.IsUsable(63));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateProxyContextId(2));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S5-R03")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdNamespaceIsPerHttpRequest()
    {
        Http3ConnectUdpContextIdRegistry firstRequest = new();
        Http3ConnectUdpContextIdRegistry secondRequest = new();

        firstRequest.AllocateClientContextId(2);
        secondRequest.AllocateClientContextId(2);

        Assert.True(firstRequest.IsUsable(2));
        Assert.True(secondRequest.IsUsable(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0081")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsMayBeAllocatedInAnyOrder()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(10);
        registry.AllocateClientContextId(2);
        registry.AllocateProxyContextId(7);

        Assert.True(registry.IsUsable(10));
        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(7));
    }

    [Fact]
    [Requirement("RFC9298-S4-P2-S5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsMustNotBeReallocatedInsideOneNamespace()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);

        Assert.Throws<InvalidOperationException>(() => registry.AllocateClientContextId(2));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0083")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AllocatedContextIdsAreUsableByEitherEndpoint()
    {
        Http3ConnectUdpContextIdRegistry registry = new();

        registry.AllocateClientContextId(2);
        registry.AllocateProxyContextId(3);

        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(3));
        Assert.False(registry.IsUsable(4));
    }

    [Fact]
    [Requirement("RFC9298-S4-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FutureExtensionsMayRegisterContextIdsWithHeadersOrCapsules()
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: true, usesCapsule: false));
        Assert.True(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: true));
        Assert.True(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: true, usesCapsule: true));
        Assert.False(Http3ConnectUdpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0085")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdDirectlyFollowsQuarterStreamIdInQuicDatagram()
    {
        Http3Datagram oneByteContextId = new Http3ConnectUdpDatagram(2, [0xAA]).ToHttp3Datagram(8);
        Http3Datagram twoByteContextId = new Http3ConnectUdpDatagram(64, [0xBB]).ToHttp3Datagram(8);

        Assert.Equal([0x02, 0x02, 0xAA], oneByteContextId.Encode());
        Assert.Equal([0x02, 0x40, 0x40, 0xBB], twoByteContextId.Encode());
        AssertDatagramError(() => Http3ConnectUdpDatagram.ParseFromHttp3Datagram(Http3Datagram.CreateForAssociatedStream(8, [])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0086")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyingPayloadIsContextIdThenPayload()
    {
        foreach ((ulong contextId, byte[] payload) in new[]
        {
            (2UL, new byte[] { 0x01, 0x02 }),
            (64UL, new byte[] { 0x03, 0x04, 0x05 }),
        })
        {
            Http3ConnectUdpDatagram parsed = Http3ConnectUdpDatagram.Parse(new Http3ConnectUdpDatagram(contextId, payload).Encode());

            Assert.Equal(contextId, parsed.ContextId);
            Assert.Equal(payload, parsed.Payload);
        }
    }

    [Fact]
    [Requirement("RFC9298-S5-P3-2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnknownContextIdIsDroppedSilentlyOrBufferedTemporarily()
    {
        Assert.Equal(Http3ConnectUdpUnknownContextAction.BufferTemporarily, Http3ConnectUdpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: true));
        Assert.Equal(Http3ConnectUdpUnknownContextAction.DropSilently, Http3ConnectUdpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: false));
    }

    [Fact]
    [Requirement("RFC9298-S5-P4-S4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpProxyingPayloadMayBeEmpty()
    {
        foreach (ulong contextId in new[] { 0UL, 2UL, 64UL })
        {
            Http3ConnectUdpDatagram datagram = new(contextId, []);

            Assert.Empty(datagram.Payload);
            Assert.Empty(Http3ConnectUdpDatagram.Parse(datagram.Encode()).Payload);
        }
    }

    [Fact]
    [Requirement("RFC9298-S5-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UdpPacketsUseHttpDatagramsWithContextIdZero()
    {
        byte[] payload = [0xCA, 0xFE];

        Http3ConnectUdpDatagram datagram = Http3ConnectUdpDatagram.CreateUdpPayload(payload);

        Assert.Equal(Http3ConnectUdpDatagram.UdpPayloadContextId, datagram.ContextId);
        Assert.Equal([0x00, 0xCA, 0xFE], datagram.Encode());
    }

    [Fact]
    [Requirement("RFC9298-S5-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdZeroCarriesUnmodifiedUdpPayload()
    {
        foreach (byte[] payload in new[] { new byte[] { 0xCA }, new byte[] { 0xCA, 0xFE }, new byte[] { 0x01, 0x02, 0x03 } })
        {
            Http3ConnectUdpDatagram datagram = Http3ConnectUdpDatagram.CreateUdpPayload(payload);

            Assert.Equal(payload, datagram.Payload);
            Assert.Equal(payload, Http3ConnectUdpDatagram.Parse(datagram.Encode()).Payload);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0092")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_EndpointsDoNotSendContextIdZeroPayloadsLongerThan65527Bytes()
    {
        Assert.Equal(Http3ConnectUdpDatagram.MaximumUdpPayloadLength, Http3ConnectUdpDatagram.CreateUdpPayload(new byte[Http3ConnectUdpDatagram.MaximumUdpPayloadLength]).Payload.Length);

        AssertDatagramError(() => Http3ConnectUdpDatagram.CreateUdpPayload(new byte[Http3ConnectUdpDatagram.MaximumUdpPayloadLength + 1]));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0093")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ReceiverAbortsStreamForOversizedContextIdZeroPayload()
    {
        byte[] encoded = new byte[Http3ConnectUdpDatagram.MaximumUdpPayloadLength + 2];
        encoded[0] = 0x00;

        AssertDatagramError(() => Http3ConnectUdpDatagram.Parse(encoded));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0094")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProxyDiscardsContextIdZeroPayloadAboveKnownOutgoingLimit()
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.ShouldDiscardForKnownOutgoingLimit(udpPayloadLength: 1201, outgoingUdpPacketLimit: 1200));
        Assert.False(Http3ConnectUdpDatagramPolicy.ShouldDiscardForKnownOutgoingLimit(udpPayloadLength: 1200, outgoingUdpPacketLimit: 1200));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9298-0095")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DiscardedDatagramCapsuleIsDroppedWithoutBuffering()
    {
        Assert.True(Http3ConnectUdpDatagramPolicy.ShouldDiscardDatagramCapsuleWhenDatagramDiscarded(transportedByDatagramCapsule: true));
        Assert.False(Http3ConnectUdpDatagramPolicy.ShouldDiscardDatagramCapsuleWhenDatagramDiscarded(transportedByDatagramCapsule: false));
    }

    private static void AssertDatagramError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);
        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }
}
