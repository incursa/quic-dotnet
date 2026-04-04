namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP2-0005">The packet number space enumeration MUST include Initial, Handshake, and ApplicationData.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP2-0005")]
public sealed class REQ_QUIC_RFC9002_SAP2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Enum_DeclaresTheThreePacketNumberSpaces()
    {
        Assert.Equal(0, (int)QuicPacketNumberSpace.Initial);
        Assert.Equal(1, (int)QuicPacketNumberSpace.Handshake);
        Assert.Equal(2, (int)QuicPacketNumberSpace.ApplicationData);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Enum_DoesNotDefineANumberSpaceOutsideTheRecommendedSet()
    {
        Assert.False(Enum.IsDefined(typeof(QuicPacketNumberSpace), 3));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void Enum_ContainsExactlyTheThreeDeclaredPacketNumberSpaces()
    {
        QuicPacketNumberSpace[] values = Enum.GetValues<QuicPacketNumberSpace>();

        Assert.Equal(3, values.Length);
        Assert.Equal(QuicPacketNumberSpace.Initial, values[0]);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, values[^1]);
    }
}
