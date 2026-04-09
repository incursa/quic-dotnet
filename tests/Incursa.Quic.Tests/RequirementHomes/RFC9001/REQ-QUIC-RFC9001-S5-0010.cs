namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S5-0010")]
public sealed class REQ_QUIC_RFC9001_S5_0010
{
    private static readonly byte[] ExpectedRetryIntegrityKey =
    [
        0xBE, 0x0C, 0x69, 0x0B, 0x9F, 0x66, 0x57, 0x5A,
        0x1D, 0x76, 0x6B, 0x54, 0xE3, 0x68, 0xC8, 0x4E,
    ];

    private static readonly byte[] ExpectedRetryIntegrityNonce =
    [
        0x46, 0x15, 0x99, 0xD3, 0x5D, 0x63, 0x2B, 0xF2,
        0x23, 0x98, 0x25, 0xBB,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetryIntegrityKeyAndNonce_UseTheRFC9001FixedValues()
    {
        Assert.True(ExpectedRetryIntegrityKey.AsSpan().SequenceEqual(QuicRetryIntegrity.RetryIntegrityKey));
        Assert.True(ExpectedRetryIntegrityNonce.AsSpan().SequenceEqual(QuicRetryIntegrity.RetryIntegrityNonce));
    }
}
