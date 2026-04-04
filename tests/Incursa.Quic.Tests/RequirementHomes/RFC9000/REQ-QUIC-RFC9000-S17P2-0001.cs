namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0001">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2-0001")]
public sealed class REQ_QUIC_RFC9000_S17P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0001">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0001")]
    public void TryClassifyHeaderForm_RecognizesLongAndShortHeadersByTheHighBit()
    {
        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: 0x11223344,
                destinationConnectionId: [0x10],
                sourceConnectionId: [0x20],
                versionSpecificData: [0x30]),
            out QuicHeaderForm longHeaderForm));
        Assert.Equal(QuicHeaderForm.Long, longHeaderForm);

        Assert.True(QuicPacketParser.TryClassifyHeaderForm(
            QuicHeaderTestData.BuildShortHeader(
                headerControlBits: 0x24,
                remainder: [0xAA]),
            out QuicHeaderForm shortHeaderForm));
        Assert.Equal(QuicHeaderForm.Short, shortHeaderForm);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2-0001">The Header Form field MUST be 1 bits long with value 1.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2-0001")]
    public void TryClassifyHeaderForm_RejectsEmptyInput()
    {
        Assert.False(QuicPacketParser.TryClassifyHeaderForm([], out _));
    }
}
