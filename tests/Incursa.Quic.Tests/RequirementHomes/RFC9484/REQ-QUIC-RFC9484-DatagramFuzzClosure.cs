// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9484_DatagramFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0150")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyingHttpDatagramsStartWithContextId()
    {
        foreach ((ulong contextId, byte[] payload) in new[]
        {
            (1UL, new byte[] { 0xCA }),
            (2UL, new byte[] { 0xCA, 0xFE }),
            (64UL, new byte[] { 0xAA }),
        })
        {
            byte[] encoded = new Http3ConnectIpDatagram(contextId, payload).Encode();
            Http3ConnectIpDatagram parsed = Http3ConnectIpDatagram.Parse(encoded);

            Assert.Equal(contextId, parsed.ContextId);
            Assert.Equal(payload, parsed.Payload);
        }

        AssertDatagramError(() => Http3ConnectIpDatagram.Parse([]));
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsAreSixtyTwoBitIntegers()
    {
        foreach (ulong contextId in new[] { 0UL, 1UL, 63UL, 64UL, Http3ConnectIpDatagram.MaximumContextId })
        {
            byte[] payload = contextId == 0 ? CreateIpv4Packet() : [];
            Assert.Equal(contextId, new Http3ConnectIpDatagram(contextId, payload).ContextId);
        }

        AssertDatagramError(() => new Http3ConnectIpDatagram(Http3ConnectIpDatagram.MaximumContextId + 1, []));
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsAreEncodedAsVariableLengthIntegers()
    {
        foreach ((ulong contextId, byte[] expectedPrefix) in new[]
        {
            (1UL, new byte[] { 0x01 }),
            (63UL, new byte[] { 0x3F }),
            (64UL, new byte[] { 0x40, 0x40 }),
        })
        {
            byte[] encoded = new Http3ConnectIpDatagram(contextId, [0xAA]).Encode();

            Assert.True(encoded.AsSpan(0, expectedPrefix.Length).SequenceEqual(expectedPrefix));
            Assert.Equal(contextId, Http3ConnectIpDatagram.Parse(encoded).ContextId);
        }

        AssertDatagramError(() => Http3ConnectIpDatagram.Parse([0x40]));
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NonZeroContextIdsMustBeDynamicallyAllocatedBeforeUse()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        foreach (ulong contextId in new[] { 2UL, 9UL, 64UL })
        {
            Assert.False(registry.IsUsable(contextId));
            registry.AllocateContextId(contextId);
            Assert.True(registry.IsUsable(contextId));
        }
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S3-R02")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdZeroIsReservedForIpPayloads()
    {
        Http3ConnectIpContextIdRegistry registry = new();
        Http3ConnectIpDatagram datagram = Http3ConnectIpDatagram.CreateIpPacketPayload(CreateIpv4Packet());

        Assert.Equal(0UL, datagram.ContextId);
        Assert.True(registry.IsUsable(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => registry.AllocateContextId(0));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0155")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsMayBeAllocatedInAnyOrder()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        foreach (ulong contextId in new[] { 10UL, 2UL, 64UL, 3UL })
        {
            registry.AllocateContextId(contextId);
            Assert.True(registry.IsUsable(contextId));
        }

        Assert.Equal(4, registry.AllocatedContextIds.Count);
    }

    [Fact]
    [Requirement("RFC9484-S5-P2-S6-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdsMustNotBeReallocatedWithinOneRequest()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        foreach (ulong contextId in new[] { 2UL, 64UL })
        {
            registry.AllocateContextId(contextId);
            Assert.Throws<InvalidOperationException>(() => registry.AllocateContextId(contextId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0157")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_AllocatedContextIdsAreUsableByEitherEndpoint()
    {
        Http3ConnectIpContextIdRegistry registry = new();

        registry.AllocateContextId(2);
        registry.AllocateContextId(9);

        Assert.True(registry.IsUsable(2));
        Assert.True(registry.IsUsable(9));
        Assert.False(registry.IsUsable(10));
    }

    [Fact]
    [Requirement("RFC9484-S5-P3-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FutureExtensionsMayRegisterContextIdsWithHeadersOrCapsules()
    {
        Assert.True(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: true, usesCapsule: false));
        Assert.True(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: true));
        Assert.True(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: true, usesCapsule: true));
        Assert.False(Http3ConnectIpDatagramPolicy.CanUseFutureContextRegistrationMechanism(usesHeaderField: false, usesCapsule: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0159")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdDirectlyFollowsQuarterStreamIdInQuicDatagramPayload()
    {
        Http3Datagram oneByteContextId = new Http3ConnectIpDatagram(2, [0xAA]).ToHttp3Datagram(8);
        Http3Datagram twoByteContextId = new Http3ConnectIpDatagram(64, [0xBB]).ToHttp3Datagram(8);

        Assert.Equal([0x02, 0x02, 0xAA], oneByteContextId.Encode());
        Assert.Equal([0x02, 0x40, 0x40, 0xBB], twoByteContextId.Encode());
        AssertDatagramError(() => Http3ConnectIpDatagram.ParseFromHttp3Datagram(Http3Datagram.CreateForAssociatedStream(8, [])));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0160")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpProxyingPayloadConsistsOfContextIdThenPayload()
    {
        foreach ((ulong contextId, byte[] payload) in new[]
        {
            (2UL, new byte[] { 0x01, 0x02 }),
            (64UL, new byte[] { 0x03, 0x04, 0x05 }),
        })
        {
            Http3ConnectIpDatagram parsed = Http3ConnectIpDatagram.Parse(new Http3ConnectIpDatagram(contextId, payload).Encode());

            Assert.Equal(contextId, parsed.ContextId);
            Assert.Equal(payload, parsed.Payload);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0161")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdFieldIsVariableLengthIntegerContainingContextIdValue()
    {
        foreach (ulong contextId in new[] { 1UL, 63UL, 64UL, 16383UL })
        {
            byte[] encoded = new Http3ConnectIpDatagram(contextId, [0xCC]).Encode();
            Assert.True(Http3ConnectIpFoundationPolicy.TryDecodeVariableLengthInteger(encoded, out ulong decoded, out int bytesConsumed));

            Assert.Equal(contextId, decoded);
            Assert.Equal(contextId, Http3ConnectIpDatagram.Parse(encoded).ContextId);
            Assert.True(bytesConsumed is 1 or 2);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0162")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_UnknownContextIdIsDroppedSilentlyOrBufferedTemporarily()
    {
        Assert.Equal(Http3ConnectIpUnknownContextAction.BufferTemporarily, Http3ConnectIpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: true));
        Assert.Equal(Http3ConnectIpUnknownContextAction.DropSilently, Http3ConnectIpDatagramPolicy.ClassifyUnknownContextId(temporaryBufferAvailable: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0163")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PayloadSemanticsDependOnContextIdValue()
    {
        Assert.True(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(0, contextIdRegistered: false));
        Assert.True(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(2, contextIdRegistered: true));
        Assert.False(Http3ConnectIpDatagramPolicy.PayloadSemanticsDependOnContextId(2, contextIdRegistered: false));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0164")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DatagramPayloadMayBeEmptyForRegisteredExtensionContextIds()
    {
        foreach (ulong contextId in new[] { 1UL, 2UL, 64UL })
        {
            Http3ConnectIpDatagram datagram = new(contextId, []);
            Http3ConnectIpDatagram parsed = Http3ConnectIpDatagram.Parse(datagram.Encode());

            Assert.Empty(datagram.Payload);
            Assert.Empty(parsed.Payload);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0165")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_IpPacketsUseHttpDatagramsWithContextIdZero()
    {
        foreach (byte[] packet in new[] { CreateIpv4Packet(), CreateIpv6Packet(payloadLength: 2) })
        {
            Http3ConnectIpDatagram datagram = Http3ConnectIpDatagram.CreateIpPacketPayload(packet);

            Assert.Equal(0UL, datagram.ContextId);
            Assert.Equal(packet, datagram.Payload);
            Assert.Equal(0x00, datagram.Encode()[0]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9484-0166")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ContextIdZeroPayloadContainsFullIpPacket()
    {
        byte[] ipv4 = CreateIpv4Packet();
        byte[] ipv6 = CreateIpv6Packet(payloadLength: 2);

        Assert.True(Http3ConnectIpDatagram.IsFullIpPacket(ipv4));
        Assert.True(Http3ConnectIpDatagram.IsFullIpPacket(ipv6));
        AssertDatagramError(() => Http3ConnectIpDatagram.CreateIpPacketPayload(ipv4[..^1]));
        AssertDatagramError(() => Http3ConnectIpDatagram.CreateIpPacketPayload(ipv6[..^1]));
    }

    [Fact]
    [Requirement("RFC9484-S7-1-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientMayOptimisticallySendIpPacketsBeforeProxyingResponse()
    {
        Assert.True(Http3ConnectIpDatagramPolicy.CanClientOptimisticallySendIpPackets(usingHttp2: true, usingHttp3: false));
        Assert.True(Http3ConnectIpDatagramPolicy.CanClientOptimisticallySendIpPackets(usingHttp2: false, usingHttp3: true));
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

    private static void AssertDatagramError(Action action)
    {
        Http3Exception exception = Assert.Throws<Http3Exception>(action);
        Assert.Equal(Http3ErrorCode.DatagramError, exception.ErrorCode);
    }
}
