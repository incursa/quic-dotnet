namespace Incursa.Quic;

internal sealed record QuicClientCertificatePolicySnapshot
{
    public QuicClientCertificatePolicySnapshot(
        ReadOnlyMemory<byte> exactPeerLeafCertificateDer,
        ReadOnlyMemory<byte> explicitTrustMaterialSha256)
    {
        ExactPeerLeafCertificateDer = CloneBytes(exactPeerLeafCertificateDer);
        ExplicitTrustMaterialSha256 = CloneBytes(explicitTrustMaterialSha256);
    }

    public ReadOnlyMemory<byte> ExactPeerLeafCertificateDer { get; }

    public ReadOnlyMemory<byte> ExplicitTrustMaterialSha256 { get; }

    public bool HasExactPeerIdentity => !ExactPeerLeafCertificateDer.IsEmpty;

    public bool HasExplicitTrustMaterial => !ExplicitTrustMaterialSha256.IsEmpty;

    public bool IsComplete => HasExactPeerIdentity && HasExplicitTrustMaterial;

    private static ReadOnlyMemory<byte> CloneBytes(ReadOnlyMemory<byte> bytes)
    {
        return bytes.IsEmpty ? ReadOnlyMemory<byte>.Empty : bytes.ToArray();
    }
}
