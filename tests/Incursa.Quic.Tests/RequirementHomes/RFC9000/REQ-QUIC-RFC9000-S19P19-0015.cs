namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0015">Because a CONNECTION_CLOSE frame MUST NOT be split between packets, any limits on packet size will also limit the space available for a reason phrase.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0015")]
public sealed class REQ_QUIC_RFC9000_S19P19_0015
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatConnectionCloseFrame_RejectsTooSmallDestinationBuffers()
    {
        QuicConnectionCloseFrame frame = new(0x1234, 0x02, [0x6F, 0x6B]);

        Assert.False(QuicFrameCodec.TryFormatConnectionCloseFrame(frame, stackalloc byte[0], out _));
    }
}
