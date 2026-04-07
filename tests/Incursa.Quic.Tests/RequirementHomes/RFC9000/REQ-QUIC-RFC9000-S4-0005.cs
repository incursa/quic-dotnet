namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4-0005")]
public sealed class REQ_QUIC_RFC9000_S4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void Constructor_ExposesConfiguredBufferCapacity()
    {
        QuicCryptoBuffer minimumBuffer = new();
        QuicCryptoBuffer configuredBuffer = new(8192);

        Assert.Equal(4096, minimumBuffer.Capacity);
        Assert.Equal(8192, configuredBuffer.Capacity);
    }
}
