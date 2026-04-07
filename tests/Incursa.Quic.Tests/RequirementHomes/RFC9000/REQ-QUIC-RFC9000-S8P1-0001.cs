namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P1-0001")]
public sealed class REQ_QUIC_RFC9000_S8P1_0001
{
    [Theory]
    [InlineData(true, 8, true)]
    [InlineData(true, 7, false)]
    [InlineData(false, 8, false)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanConsiderPeerAddressValidated_RequiresEndpointChosenAndAtLeast64BitsOfEntropy(
        bool chosenByEndpoint,
        int connectionIdLength,
        bool expected)
    {
        byte[] connectionId = Enumerable.Range(0, connectionIdLength).Select(index => (byte)index).ToArray();

        Assert.Equal(expected, QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint));
    }
}
