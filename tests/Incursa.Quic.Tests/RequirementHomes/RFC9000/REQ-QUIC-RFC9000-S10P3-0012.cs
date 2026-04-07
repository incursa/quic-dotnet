namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0012">Endpoints MUST discard packets that are too small to be valid QUIC packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3-0012")]
public sealed class REQ_QUIC_RFC9000_S10P3_0012
{
    public static TheoryData<byte[]> TruncatedLongHeaderCases => new()
    {
        { [] },
        { [0x80] },
        { [0x80, 0x00, 0x00, 0x00, 0x01] },
        { [0x80, 0x00, 0x00, 0x00, 0x01, 0x00] },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x52, 0x01020304, [0x11, 0x12], [0x21], [], 1) },
        { QuicHeaderTestData.BuildTruncatedLongHeader(0x52, 0x01020304, [0x11, 0x12], [0x21, 0x22], [], 1) },
    };

    public static TheoryData<byte[]> InvalidInitialVersionSpecificDataCases => new()
    {
        { [] },
        { [0x40] },
        { [0x02, 0xAA] },
        { [0x00] },
        { [0x00, 0x40] },
        { [0x00, 0x00] },
        { [0x00, 0x02, 0xAA] },
    };

    public static TheoryData<byte[]> InvalidZeroRttVersionSpecificDataCases => new()
    {
        { [] },
        { [0x40] },
        { [0x00] },
        { [0x02, 0xAA] },
    };

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseShortHeader_AcceptsAValidShortHeaderPacket()
    {
        byte[] remainder = [0xAA, 0xBB];
        byte[] packet = QuicHeaderTestData.BuildShortHeader(
            headerControlBits: 0x24,
            remainder: remainder);

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket parsed));
        Assert.Equal(QuicHeaderForm.Short, parsed.HeaderForm);
        Assert.Equal((byte)0x64, parsed.HeaderControlBits);
        Assert.True(parsed.Remainder.SequenceEqual(remainder));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseShortHeader_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryParseShortHeader([], out _));
    }

    [Theory]
    [MemberData(nameof(TruncatedLongHeaderCases))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC8999-S5P1-0006">The byte after the Destination Connection ID field MUST encode the Source Connection ID length as an 8-bit unsigned integer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3-0012">Endpoints MUST discard packets that are too small to be valid QUIC packets.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0008">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0009">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0010">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P2-0011">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0011">The Destination Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0012">The Destination Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0013">The Source Connection ID Length field MUST be 8 bits long.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P3-0014">The Source Connection ID field MUST be between 0 and 160 bits long.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC8999-S5P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0008")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0010")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P2-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0012")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S17P2P3-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseLongHeader_RejectsTruncatedInputs(byte[] packet)
    {
        Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
    }
}
