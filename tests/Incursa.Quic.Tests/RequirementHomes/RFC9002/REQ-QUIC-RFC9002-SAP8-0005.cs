namespace Incursa.Quic.Tests;

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
