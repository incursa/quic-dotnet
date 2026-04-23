namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP2-0003")]
public sealed class REQ_QUIC_RFC9002_SBP2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ComputeBytesInFlightBytes_IncludesQuicHeaderProtectedPayloadAndAeadOverhead()
    {
        ulong accountedBytes = QuicCongestionControlState.ComputeBytesInFlightBytes(
            quicHeaderBytes: 22,
            protectedPayloadBytes: 1_000,
            aeadOverheadBytes: 16,
            ipOverheadBytes: 20,
            udpOverheadBytes: 8);

        Assert.Equal(1_038UL, accountedBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ComputeBytesInFlightBytes_ExcludesIpAndUdpOverhead()
    {
        ulong withTransportOverhead = QuicCongestionControlState.ComputeBytesInFlightBytes(
            quicHeaderBytes: 22,
            protectedPayloadBytes: 1_000,
            aeadOverheadBytes: 16,
            ipOverheadBytes: 20,
            udpOverheadBytes: 8);
        ulong withoutTransportOverhead = QuicCongestionControlState.ComputeBytesInFlightBytes(
            quicHeaderBytes: 22,
            protectedPayloadBytes: 1_000,
            aeadOverheadBytes: 16);

        Assert.Equal(withoutTransportOverhead, withTransportOverhead);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RegisterPacketSent_UsesTheComputedQuicPayloadBytesForBytesInFlight()
    {
        QuicCongestionControlState state = new();
        ulong accountedBytes = QuicCongestionControlState.ComputeBytesInFlightBytes(
            quicHeaderBytes: 22,
            protectedPayloadBytes: 1_000,
            aeadOverheadBytes: 16,
            ipOverheadBytes: 20,
            udpOverheadBytes: 8);

        state.RegisterPacketSent(accountedBytes);

        Assert.Equal(1_038UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FuzzBytesInFlightAccountingNeverIncludesTransportOverhead()
    {
        Random random = new(unchecked((int)0x9002_0003));

        for (int i = 0; i < 128; i++)
        {
            ulong quicHeaderBytes = (ulong)random.Next(1, 128);
            ulong protectedPayloadBytes = (ulong)random.Next(0, 1_500);
            ulong aeadOverheadBytes = (ulong)random.Next(0, 32);
            ulong ipOverheadBytes = (ulong)random.Next(20, 64);
            ulong udpOverheadBytes = (ulong)random.Next(8, 16);

            ulong accountedBytes = QuicCongestionControlState.ComputeBytesInFlightBytes(
                quicHeaderBytes,
                protectedPayloadBytes,
                aeadOverheadBytes,
                ipOverheadBytes,
                udpOverheadBytes);

            Assert.Equal(quicHeaderBytes + protectedPayloadBytes + aeadOverheadBytes, accountedBytes);
        }
    }
}
