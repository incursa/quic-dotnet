namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP8-0005">`PeerCompletedAddressValidation` MUST return true for servers and for clients only after a Handshake ACK has been received or the handshake has been confirmed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP8-0005")]
public sealed class REQ_QUIC_RFC9002_SAP8_0005
{
    [Theory]
    [InlineData(true, false, false, true)]
    [InlineData(false, true, false, true)]
    [InlineData(false, false, true, true)]
    [InlineData(false, false, false, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Property")]
    public void PeerCompletedAddressValidation_RequiresServerRoleOrHandshakeProof(
        bool isServer,
        bool handshakeAckReceived,
        bool handshakeConfirmed,
        bool expectedCompleted)
    {
        Assert.Equal(expectedCompleted, QuicAddressValidation.PeerCompletedAddressValidation(
            isServer,
            handshakeAckReceived,
            handshakeConfirmed));
    }
}
