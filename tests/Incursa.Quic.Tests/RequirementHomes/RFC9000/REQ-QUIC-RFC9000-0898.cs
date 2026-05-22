namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0898">Versions with the most significant 16 bits of the version number cleared MUST be reserved for use in future IETF consensus documents.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0898")]
public sealed class REQ_QUIC_RFC9000_0898
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0898">Versions with the most significant 16 bits of the version number cleared MUST be reserved for use in future IETF consensus documents.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0898")]
    public void IsFutureIetfConsensusReservedVersion_RecognizesTheClearedTopHalfRange()
    {
        Assert.True(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(0x00000000));
        Assert.True(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(0x00001234));
        Assert.True(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(0x0000FFFF));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0898">Versions with the most significant 16 bits of the version number cleared MUST be reserved for use in future IETF consensus documents.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-0898")]
    public void IsFutureIetfConsensusReservedVersion_RejectsVersionsWithAnyTopBitsSet()
    {
        Assert.False(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(0x00010000));
        Assert.False(QuicVersionNegotiation.IsFutureIetfConsensusReservedVersion(0x11223344));
    }
}
