// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9002_SAP1P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1P1-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketRecord_PreservesPacketNumbers()
    {
        foreach ((QuicPersistentCongestionPacket packet, SentPacketExpectation expected) in CreateSentPacketCases())
        {
            Assert.Equal(expected.PacketNumber, packet.PacketNumber);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1P1-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketRecord_PreservesAckElicitingStatus()
    {
        foreach ((QuicPersistentCongestionPacket packet, SentPacketExpectation expected) in CreateSentPacketCases())
        {
            Assert.Equal(expected.AckEliciting, packet.AckEliciting);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1P1-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketRecord_PreservesBytesInFlightParticipation()
    {
        foreach ((QuicPersistentCongestionPacket packet, SentPacketExpectation expected) in CreateSentPacketCases())
        {
            Assert.Equal(expected.InFlight, packet.InFlight);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1P1-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketRecord_PreservesSentBytes()
    {
        foreach ((QuicPersistentCongestionPacket packet, SentPacketExpectation expected) in CreateSentPacketCases())
        {
            Assert.Equal(expected.SentBytes, packet.SentBytes);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9002-SAP1P1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_SentPacketRecord_PreservesSendTimes()
    {
        foreach ((QuicPersistentCongestionPacket packet, SentPacketExpectation expected) in CreateSentPacketCases())
        {
            Assert.Equal(expected.SentAtMicros, packet.SentAtMicros);
        }
    }

    private static (QuicPersistentCongestionPacket Packet, SentPacketExpectation Expected)[] CreateSentPacketCases() =>
        [
            CreatePacketCase(
                QuicPacketNumberSpace.Initial,
                sentAtMicros: 1,
                sentBytes: 1,
                ackEliciting: true,
                inFlight: true,
                acknowledged: false,
                lost: false,
                packetNumber: 0),
            CreatePacketCase(
                QuicPacketNumberSpace.Handshake,
                sentAtMicros: 1_000,
                sentBytes: 1_200,
                ackEliciting: true,
                inFlight: false,
                acknowledged: true,
                lost: false,
                packetNumber: 41),
            CreatePacketCase(
                QuicPacketNumberSpace.ApplicationData,
                sentAtMicros: 2_500,
                sentBytes: 64,
                ackEliciting: false,
                inFlight: false,
                acknowledged: true,
                lost: false,
                packetNumber: 4_294_967_295UL),
            CreatePacketCase(
                QuicPacketNumberSpace.ApplicationData,
                sentAtMicros: 65_535,
                sentBytes: 16_384,
                ackEliciting: true,
                inFlight: true,
                acknowledged: false,
                lost: true,
                packetNumber: 9_007_199_254_740_991UL),
        ];

    private static (QuicPersistentCongestionPacket Packet, SentPacketExpectation Expected) CreatePacketCase(
        QuicPacketNumberSpace packetNumberSpace,
        ulong sentAtMicros,
        ulong sentBytes,
        bool ackEliciting,
        bool inFlight,
        bool acknowledged,
        bool lost,
        ulong packetNumber)
    {
        QuicPersistentCongestionPacket packet = new(
            packetNumberSpace,
            sentAtMicros,
            sentBytes,
            ackEliciting,
            inFlight,
            acknowledged,
            lost,
            packetNumber);

        SentPacketExpectation expected = new(
            sentAtMicros,
            sentBytes,
            ackEliciting,
            inFlight,
            packetNumber);

        return (packet, expected);
    }

    private readonly record struct SentPacketExpectation(
        ulong SentAtMicros,
        ulong SentBytes,
        bool AckEliciting,
        bool InFlight,
        ulong PacketNumber);
}
