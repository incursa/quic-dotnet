namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0004">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
public sealed class REQ_QUIC_RFC9000_S8P1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryGetVersion1InitialDatagramPaddingLength_UsesTheExactMinimumPayloadBoundary()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1200, out int paddingLength));

        Assert.Equal(0, paddingLength);
    }
}
