namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0159")]
public sealed class REQ_QUIC_RFC9000_0159
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
