// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S12-2-P5-S1-R01">The receiver of coalesced QUIC packets MUST individually process each QUIC packet and separately acknowledge each QUIC packet, as if the packets were received as the payload of different UDP datagrams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S12-2-P5-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S12P2_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-0851")]
    [Trait("Category", "Positive")]
    public void RuntimeProcessesTheTrailingHandshakePacketAfterTheLeadingInitialPacket()
    {
        QuicCoalescedPacketRuntimeTestSupport.CoalescedServerFlightScenario scenario =
            QuicCoalescedPacketRuntimeTestSupport.CreateClientRuntimeWithCoalescedServerFlight();

        Assert.True(QuicPacketParser.TryGetPacketLength(scenario.CoalescedDatagram, out int firstPacketLength));
        Assert.Equal(scenario.InitialPacket.Length, firstPacketLength);

        ReadOnlySpan<byte> remainingDatagram = scenario.CoalescedDatagram.AsSpan(firstPacketLength);
        Assert.True(QuicPacketParser.TryGetPacketLength(remainingDatagram, out int secondPacketLength));
        Assert.Equal(scenario.HandshakePacket.Length, secondPacketLength);

        QuicConnectionTransitionResult result = scenario.ClientRuntime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                PathIdentity: scenario.PathIdentity,
                Datagram: scenario.CoalescedDatagram),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.True(scenario.ClientRuntime.TlsState.PeerTransportParametersCommitted);
        Assert.NotNull(scenario.ClientRuntime.TlsState.PeerTransportParameters);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S14-0002")]
    [Trait("Category", "Positive")]
    public void TryParseLongHeader_IndividuallyExposesEveryPacketInACoalescedDatagram()
    {
        byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
            token: [0xA1],
            packetNumber: [0x01, 0x02],
            protectedPayload: [0xB1]);
        byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x42,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            firstVersionSpecificData);
        byte[] secondVersionSpecificData = QuicHeaderTestData.BuildZeroRttVersionSpecificData(
            packetNumber: [0x02, 0x03],
            protectedPayload: [0xB2]);
        byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
            headerControlBits: 0x62,
            version: 1,
            destinationConnectionId: [0x10, 0x11],
            sourceConnectionId: [0x20],
            secondVersionSpecificData);
        byte[] thirdPacket = QuicHeaderTestData.BuildShortHeader(0x24, [0xC0, 0xC1, 0xC2]);
        byte[] datagram = [.. firstPacket, .. secondPacket, .. thirdPacket];

        Assert.Equal(firstPacket.Length + secondPacket.Length + thirdPacket.Length, datagram.Length);
        Assert.True(QuicPacketParser.TryParseLongHeader(datagram[..firstPacket.Length], out QuicLongHeaderPacket firstHeader));
        Assert.Equal(firstPacket.Length, 1 + 4 + 1 + firstHeader.DestinationConnectionIdLength + 1 + firstHeader.SourceConnectionIdLength + firstHeader.VersionSpecificData.Length);
        Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(firstHeader.VersionSpecificData));

        Assert.True(QuicPacketParser.TryParseLongHeader(datagram.AsSpan(firstPacket.Length, secondPacket.Length), out QuicLongHeaderPacket secondHeader));
        Assert.Equal(secondPacket.Length, 1 + 4 + 1 + secondHeader.DestinationConnectionIdLength + 1 + secondHeader.SourceConnectionIdLength + secondHeader.VersionSpecificData.Length);
        Assert.True(secondVersionSpecificData.AsSpan().SequenceEqual(secondHeader.VersionSpecificData));

        Assert.True(QuicPacketParser.TryParseShortHeader(datagram.AsSpan(firstPacket.Length + secondPacket.Length, thirdPacket.Length), out QuicShortHeaderPacket thirdHeader));
        Assert.True(thirdPacket.AsSpan(1).SequenceEqual(thirdHeader.Remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryGetPacketLength_WalksEachPacketInCoalescedDatagramsSeparately()
    {
        for (int payloadLength = 0; payloadLength <= 5; payloadLength++)
        {
            byte[] firstPayload = CreateSequentialBytes((byte)(0xB0 + payloadLength), payloadLength + 1);
            byte[] secondPayload = CreateSequentialBytes((byte)(0xC0 + payloadLength), payloadLength + 2);
            byte[] thirdPayload = CreateSequentialBytes((byte)(0xD0 + payloadLength), payloadLength + 3);
            byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x42,
                version: 1,
                destinationConnectionId: [0x10, (byte)payloadLength],
                sourceConnectionId: [0x20],
                QuicHeaderTestData.BuildInitialVersionSpecificData(
                    token: [(byte)(0xA0 + payloadLength)],
                    packetNumber: [0x01, 0x02],
                    protectedPayload: firstPayload));
            byte[] secondPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x62,
                version: 1,
                destinationConnectionId: [0x10, (byte)payloadLength],
                sourceConnectionId: [0x20],
                QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    packetNumber: [0x03, 0x04],
                    protectedPayload: secondPayload));
            byte[] thirdPacket = QuicHeaderTestData.BuildShortHeader(
                0x24,
                thirdPayload);
            byte[] datagram = [.. firstPacket, .. secondPacket, .. thirdPacket];

            Assert.True(QuicPacketParser.TryGetPacketLength(datagram, out int firstPacketLength));
            Assert.Equal(firstPacket.Length, firstPacketLength);
            Assert.True(QuicPacketParser.TryGetPacketLength(datagram.AsSpan(firstPacketLength), out int secondPacketLength));
            Assert.Equal(secondPacket.Length, secondPacketLength);

            ReadOnlySpan<byte> trailingPacket = datagram.AsSpan(firstPacketLength + secondPacketLength);
            Assert.True(QuicPacketParser.TryParseShortHeader(trailingPacket, out QuicShortHeaderPacket trailingHeader));
            Assert.True(thirdPayload.AsSpan().SequenceEqual(trailingHeader.Remainder));
            Assert.Equal(datagram.Length, firstPacketLength + secondPacketLength + trailingPacket.Length);
        }
    }

    private static byte[] CreateSequentialBytes(byte start, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(start + index));
        }

        return bytes;
    }
}
