namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0011">If the last 16 bytes of the datagram are identical in value to a stateless reset token, the endpoint MUST enter the draining period.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P1-0011")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandlePotentialStatelessReset_TransitionsToDrainingWhenTheTokenMatches()
    {
        byte[] statelessResetToken =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];

        Span<byte> datagram = stackalloc byte[QuicStatelessReset.MinimumDatagramLength];
        Assert.True(QuicStatelessReset.TryFormatStatelessResetDatagram(
            statelessResetToken,
            QuicStatelessReset.MinimumDatagramLength,
            datagram,
            out int bytesWritten));

        QuicConnectionLifecycleState state = new();
        Assert.True(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
        Assert.False(state.TryHandlePotentialStatelessReset(datagram[..bytesWritten], statelessResetToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryHandlePotentialStatelessReset_DoesNotEnterDrainingWhenTheTokenDoesNotMatch()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x30);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x50);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.False(state.TryHandlePotentialStatelessReset(datagram, nonMatchingToken));
        Assert.False(state.IsDraining);
        Assert.True(state.CanSendPackets);
    }
}
