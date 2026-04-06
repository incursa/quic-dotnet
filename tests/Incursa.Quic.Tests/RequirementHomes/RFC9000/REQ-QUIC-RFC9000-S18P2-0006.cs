namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0006">A server that does not send this transport parameter MUST NOT use stateless reset (Section 10.3) for the connection ID negotiated during the handshake.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S18P2-0006")]
public sealed class REQ_QUIC_RFC9000_S18P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0006">A server that does not send this transport parameter MUST NOT use stateless reset (Section 10.3) for the connection ID negotiated during the handshake.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0006")]
    public void MatchesAnyStatelessResetToken_AllowsMatchingDatagramsWhenTheTokenIsAdvertised()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x40);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, statelessResetToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S18P2-0006">A server that does not send this transport parameter MUST NOT use stateless reset (Section 10.3) for the connection ID negotiated during the handshake.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S18P2-0006")]
    public void MatchesAnyStatelessResetToken_RejectsDatagramsWhenNoTokenWasAdvertised()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x40);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, []));
    }
}
