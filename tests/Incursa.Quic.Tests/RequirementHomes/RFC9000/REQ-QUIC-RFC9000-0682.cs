// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0682">Receivers MUST be able to process coalesced packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0682")]
public sealed class REQ_QUIC_RFC9000_0682
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeAcceptsACoalescedServerFlightDuringHandshake()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(scenario.ClientRuntime.TlsState.HandshakeKeysAvailable);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_AllowsReceiversToProcessTwoLengthDelimitedPacketsInTheSameDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA0],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x03, 0x04],
            protectedPayload: [0xC0]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            secondVersionSpecificData);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket firstHeader));
        Assert.Equal(firstPacket.Length, 1 + 4 + 1 + firstHeader.DestinationConnectionIdLength + 1 + firstHeader.SourceConnectionIdLength + firstHeader.VersionSpecificData.Length);
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(firstHeader.VersionSpecificData));
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram.AsSpan(firstPacket.Length), out QuicLongHeaderPacket secondHeader));
        Assert.Equal((byte)0x02, secondHeader.LongPacketTypeBits);
        Assert.True(secondVersionSpecificData.AsSpan().SequenceEqual(secondHeader.VersionSpecificData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryGetPacketLength_RejectsCoalescedDatagramWhenLeadingLengthExceedsAvailableBytes()
    {
        byte[] firstVersionSpecificData = BuildInitialVersionSpecificDataWithDeclaredPayloadLength(
            token: [0xA0],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB0],
            declaredPayloadLength: 64);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x03, 0x04],
            protectedPayload: [0xC0]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            secondVersionSpecificData);
        byte[] datagram = [.. firstPacket, .. secondPacket];

        Assert.False(QuicPacketParser.TryGetPacketLength(datagram, out int packetLength));
        Assert.Equal(0, packetLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryGetPacketLength_FuzzWalksLengthDelimitedCoalescedPackets()
    {
        for (int payloadLength = 0; payloadLength <= 6; payloadLength++)
        {
            byte[] firstPayload = Enumerable.Range(0, payloadLength)
                .Select(value => (byte)(0xB0 + value))
                .ToArray();
            byte[] secondPayload = Enumerable.Range(0, payloadLength + 1)
                .Select(value => (byte)(0xC0 + value))
                .ToArray();
            byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x41,
                version: 1,
                destinationConnectionId: [0x10, (byte)payloadLength],
                sourceConnectionId: [0x20],
                QuicHeaderTestData.BuildInitialVersionSpecificData(
                    token: [(byte)(0xA0 + payloadLength)],
                    packetNumber: [0x01, 0x02],
                    protectedPayload: firstPayload));
            byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x61,
                version: 1,
                destinationConnectionId: [0x10, (byte)payloadLength],
                sourceConnectionId: [0x20],
                QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    packetNumber: [0x03, 0x04],
                    protectedPayload: secondPayload));
            byte[] datagram = [.. firstPacket, .. secondPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int firstPacketLength));
            Assert.Equal(firstPacket.Length, firstPacketLength);
            Assert.True(QuicPacketParser.TryGetPacketLength(datagram.AsSpan(firstPacketLength), out int secondPacketLength));
            Assert.Equal(secondPacket.Length, secondPacketLength);
            Assert.Equal(datagram.Length, firstPacketLength + secondPacketLength);
        }
    }

    private static byte[] BuildInitialVersionSpecificDataWithDeclaredPayloadLength(
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> packetNumber,
        ReadOnlySpan<byte> protectedPayload,
        ulong declaredPayloadLength)
    {
        byte[] tokenLengthBytes = QuicVarintTestData.EncodeMinimal((ulong)token.Length);
        byte[] payloadLengthBytes = QuicVarintTestData.EncodeMinimal(declaredPayloadLength);
        byte[] versionSpecificData = new byte[
            tokenLengthBytes.Length
            + token.Length
            + payloadLengthBytes.Length
            + packetNumber.Length
            + protectedPayload.Length];

        int offset = 0;
        tokenLengthBytes.CopyTo(versionSpecificData, offset);
        offset += tokenLengthBytes.Length;
        token.CopyTo(versionSpecificData.AsSpan(offset));
        offset += token.Length;
        payloadLengthBytes.CopyTo(versionSpecificData, offset);
        offset += payloadLengthBytes.Length;
        packetNumber.CopyTo(versionSpecificData.AsSpan(offset));
        offset += packetNumber.Length;
        protectedPayload.CopyTo(versionSpecificData.AsSpan(offset));

        return versionSpecificData;
    }
}
