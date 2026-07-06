// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P4_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void SpinBitHeaderFuzz_ObserversMeasureTogglesOnlyFromOneRttShortHeaders()
    {
        for (int iteration = 0; iteration < 64; iteration++)
        {
            bool firstSpin = (iteration & 1) == 0;
            long firstObservedAtTicks = 100L + iteration;
            long secondObservedAtTicks = firstObservedAtTicks + 17L + iteration;
            long thirdObservedAtTicks = secondObservedAtTicks + 23L + iteration;
            SpinBitObservation[] observations =
            [
                new(BuildShortHeader(firstSpin), firstObservedAtTicks),
                new(BuildShortHeader(!firstSpin), secondObservedAtTicks),
                new(BuildShortHeader(firstSpin), thirdObservedAtTicks),
            ];

            Assert.True(TryMeasureSpinBitToggleInterval(observations, out long elapsedTicks));
            Assert.Equal(thirdObservedAtTicks - secondObservedAtTicks, elapsedTicks);

            byte[] oneRttPacket = BuildShortHeader(firstSpin);
            Assert.True(QuicPacketParser.TryParseShortHeader(oneRttPacket, out QuicShortHeaderPacket shortHeader));
            Assert.Equal(firstSpin, shortHeader.SpinBit);
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(oneRttPacket, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

            byte[] initialPacket = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: 1,
                destinationConnectionId: [0x11],
                sourceConnectionId: [0x22],
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                    token: [],
                    packetNumber: [(byte)iteration],
                    protectedPayload: [0x33]));
            Assert.False(QuicPacketParser.TryParseShortHeader(initialPacket, out _));
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(initialPacket, out packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.Initial, packetNumberSpace);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P4-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StoredPathSpinBitFuzz_LocalOneRttCloseUsesTheCurrentPathStoredValue()
    {
        foreach ((QuicTlsRole Role, bool ReceivedSpinBit, bool ExpectedStoredSpinBit) in new[]
        {
            (QuicTlsRole.Server, false, false),
            (QuicTlsRole.Server, true, true),
            (QuicTlsRole.Client, false, true),
            (QuicTlsRole.Client, true, false),
        })
        {
            using QuicConnectionRuntime runtime = QuicS17P4SpinBitTestSupport.CreateActiveOneRttRuntime(Role);

            QuicConnectionTransitionResult receiveResult = QuicS17P4SpinBitTestSupport.ReceivePeerPingPacket(
                runtime,
                ReceivedSpinBit,
                packetNumber: 7,
                observedAtTicks: 10);

            Assert.True(receiveResult.StateChanged);
            QuicS17P4SpinBitTestSupport.AssertLocalOneRttCloseSpinBit(
                runtime,
                ExpectedStoredSpinBit,
                observedAtTicks: 20);
        }
    }

    private static byte[] BuildShortHeader(bool spinBit)
    {
        return QuicHeaderTestData.BuildShortHeader((byte)(spinBit ? QuicPacketHeaderBits.SpinBitMask : 0x00), [0xA1, 0xA2]);
    }

    private static bool TryMeasureSpinBitToggleInterval(
        SpinBitObservation[] observations,
        out long elapsedTicks)
    {
        elapsedTicks = default;
        if (observations.Length < 3)
        {
            return false;
        }

        if (!QuicPacketParser.TryParseShortHeader(observations[0].Packet, out QuicShortHeaderPacket firstHeader)
            || !QuicPacketParser.TryParseShortHeader(observations[1].Packet, out QuicShortHeaderPacket secondHeader)
            || !QuicPacketParser.TryParseShortHeader(observations[2].Packet, out QuicShortHeaderPacket thirdHeader))
        {
            return false;
        }

        if (firstHeader.SpinBit == secondHeader.SpinBit
            || secondHeader.SpinBit == thirdHeader.SpinBit)
        {
            return false;
        }

        elapsedTicks = observations[2].ObservedAtTicks - observations[1].ObservedAtTicks;
        return true;
    }

    private readonly record struct SpinBitObservation(byte[] Packet, long ObservedAtTicks);
}
