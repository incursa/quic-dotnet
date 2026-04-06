namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0003">Connection IDs MUST ensure that changes in lower-layer addressing do not cause packets for a QUIC connection to be delivered to the wrong endpoint.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1-0003")]
public sealed class REQ_QUIC_RFC9000_S5P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1-0003">Connection IDs MUST ensure that changes in lower-layer addressing do not cause packets for a QUIC connection to be delivered to the wrong endpoint.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1-0003")]
    public void TryParseShortHeader_PreservesTheOpaqueConnectionIdRemainder()
    {
        byte[] packet = QuicHeaderTestData.BuildShortHeader(0x24, [0xAA, 0xBB, 0xCC]);
        byte[] expectedRemainder = [0xAA, 0xBB, 0xCC];

        Assert.True(QuicPacketParser.TryParseShortHeader(packet, out QuicShortHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Short, header.HeaderForm);
        Assert.Equal((byte)0x24, header.HeaderControlBits);
        Assert.Equal(3, header.Remainder.Length);
        Assert.True(expectedRemainder.AsSpan().SequenceEqual(header.Remainder));
    }
}
