namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7-0005")]
public sealed class REQ_QUIC_RFC9000_S7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TwoConnectionsExposeDistinctHandshakeKeyShares()
    {
        QuicTlsTransportBridgeDriver firstDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x11));
        QuicTlsTransportBridgeDriver secondDriver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x22));

        Assert.False(firstDriver.LocalHandshakeKeyShare.IsEmpty);
        Assert.False(secondDriver.LocalHandshakeKeyShare.IsEmpty);
        Assert.False(firstDriver.LocalHandshakeKeyShare.Span.SequenceEqual(secondDriver.LocalHandshakeKeyShare.Span));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EachConnectionKeepsItsOwnHandshakeKeyShareStable()
    {
        QuicTlsTransportBridgeDriver driver = new(
            QuicTlsRole.Client,
            localHandshakePrivateKey: QuicS7P2ServerConnectionIdTestSupport.CreateScalar(0x33));

        ReadOnlySpan<byte> firstKeyShare = driver.LocalHandshakeKeyShare.Span;
        ReadOnlySpan<byte> secondKeyShare = driver.LocalHandshakeKeyShare.Span;

        Assert.False(driver.LocalHandshakeKeyShare.IsEmpty);
        Assert.Equal(firstKeyShare.Length, secondKeyShare.Length);
        Assert.True(firstKeyShare.SequenceEqual(secondKeyShare));
    }
}
