// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Sockets;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S14_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DatagramSizeFuzz_CountsOnlyQuicPacketHeadersAndProtectedPayloads()
    {
        Random random = new(0x5140_0002);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] firstVersionSpecificData = QuicHeaderTestData.BuildInitialVersionSpecificData(
                token: RandomBytes(random, iteration % 4),
                packetNumber: RandomBytes(random, 3),
                protectedPayload: RandomBytes(random, iteration % 16));
            byte[] firstPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x42,
                version: QuicVersionNegotiation.Version1,
                destinationConnectionId: RandomBytes(random, iteration % 8),
                sourceConnectionId: RandomBytes(random, (iteration + 3) % 8),
                firstVersionSpecificData);
            byte[] secondPacket = QuicHeaderTestData.BuildShortHeader(0x24, RandomBytes(random, iteration % 8));
            byte[] datagram = [.. firstPacket, .. secondPacket];

            Assert.Equal(firstPacket.Length + secondPacket.Length, datagram.Length);
            Assert.True(QuicPacketParser.TryParseLongHeader(datagram.AsSpan(0, firstPacket.Length), out QuicLongHeaderPacket firstHeader));
            Assert.True(firstVersionSpecificData.AsSpan().SequenceEqual(firstHeader.VersionSpecificData));
            Assert.True(QuicPacketParser.TryParseShortHeader(datagram.AsSpan(firstPacket.Length), out QuicShortHeaderPacket secondHeader));
            Assert.Equal(secondPacket.Length - 1, secondHeader.Remainder.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14-0003")]
    [Requirement("REQ-QUIC-RFC9000-S14-0005")]
    [Requirement("REQ-QUIC-RFC9000-S14-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MaximumDatagramSizeFuzz_TracksDiscoveredUdpPayloadLimitAndRejectsOversizedOrdinarySends()
    {
        ulong minimum = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        for (ulong discoveredSize = minimum; discoveredSize <= minimum + 256; discoveredSize += 17)
        {
            QuicConnectionPathMaximumDatagramSizeState state = QuicConnectionPathMaximumDatagramSizeState.CreateInitial()
                .WithMaximumDatagramSize(discoveredSize);
            QuicCongestionControlState congestion = new();

            congestion.UpdateMaxDatagramSize(discoveredSize, resetToInitialWindow: false);

            Assert.Equal(discoveredSize, state.MaximumDatagramSizeBytes);
            Assert.Equal(discoveredSize, congestion.MaxDatagramSizeBytes);
            Assert.True(state.CanSend(discoveredSize));
            Assert.False(state.CanSend(discoveredSize + 1));
            Assert.True(state.CanSend(discoveredSize + 1, isProbePacket: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DontFragmentFuzz_EnablesIpv4DontFragmentWhenTheSocketSupportsIt()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            Assert.True(QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket));
            Assert.True(socket.DontFragment);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S14-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReceivedDatagramSizeFuzz_DoesNotPromoteTheActivePathMaximumDatagramSize()
    {
        ulong minimum = QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes;

        for (int iteration = 0; iteration < 32; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
            QuicConnectionPathIdentity activePath = new($"203.0.113.{20 + iteration}", RemotePort: 443);
            byte[] datagram = new byte[checked((int)(minimum + (ulong)(iteration * 11)))];

            QuicConnectionTransitionResult result = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: iteration + 1,
                    activePath,
                    datagram),
                nowTicks: iteration + 1);

            Assert.True(result.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(activePath, runtime.ActivePath.Value.Identity);
            Assert.Equal(minimum, runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
            Assert.Equal(minimum, runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
            Assert.Equal((ulong)datagram.Length, runtime.ActivePath.Value.AmplificationState.ReceivedPayloadBytes);
        }
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
