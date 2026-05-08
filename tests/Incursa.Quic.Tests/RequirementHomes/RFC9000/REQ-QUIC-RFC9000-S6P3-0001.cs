namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
public sealed class REQ_QUIC_RFC9000_S6P3_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void IsReservedVersion_UsesTheReservedPattern()
    {
        Assert.True(QuicVersionNegotiation.IsReservedVersion(0x0A0A0A0A));
        Assert.False(QuicVersionNegotiation.IsReservedVersion(0x01020304));
        Assert.Equal((uint)0x0A1A2A3A, QuicVersionNegotiation.CreateReservedVersion(0x00112233));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S6P3-0001">Endpoints MAY add reserved versions to any field where unknown or unsupported versions are ignored to test that a peer correctly ignores the value.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S6P3-0001")]
    public void ShouldDiscardVersionNegotiation_IgnoresReservedVersionAdvertisements()
    {
        uint reservedVersion = QuicVersionNegotiation.CreateReservedVersion(0x11223344);
        byte[] packet = new byte[64];

        Assert.True(QuicVersionNegotiation.TryFormatVersionNegotiationResponse(
            QuicVersionNegotiation.Version1,
            [0x10, 0x11],
            [0x20],
            [reservedVersion],
            packet,
            out int bytesWritten));

        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            packet.AsSpan(0, bytesWritten),
            out QuicVersionNegotiationPacket parsed));
        Assert.True(parsed.ContainsSupportedVersion(reservedVersion));
        Assert.False(QuicVersionNegotiation.ShouldDiscardVersionNegotiation(
            parsed,
            QuicVersionNegotiation.Version1,
            hasSuccessfullyProcessedAnotherPacket: false));
        Assert.True(QuicVersionNegotiation.ShouldAbandonConnectionAttempt(
            parsed,
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1],
            hasSuccessfullyProcessedAnotherPacket: false));
    }
}
