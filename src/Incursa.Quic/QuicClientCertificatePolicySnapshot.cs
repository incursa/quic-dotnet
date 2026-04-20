namespace Incursa.Quic;

/// <summary>
/// Captures the client-certificate policy inputs that can be reused across QUIC connection setup.
/// </summary>
internal sealed record QuicClientCertificatePolicySnapshot
{
    /// <summary>
    /// Initializes a snapshot from the exact peer leaf certificate and explicit trust material hash.
    /// </summary>
    public QuicClientCertificatePolicySnapshot(
        ReadOnlyMemory<byte> exactPeerLeafCertificateDer,
        ReadOnlyMemory<byte> explicitTrustMaterialSha256)
    {
        ExactPeerLeafCertificateDer = CloneBytes(exactPeerLeafCertificateDer);
        ExplicitTrustMaterialSha256 = CloneBytes(explicitTrustMaterialSha256);
    }

    /// <summary>
    /// Gets the exact peer leaf certificate in DER form.
    /// </summary>
    public ReadOnlyMemory<byte> ExactPeerLeafCertificateDer { get; }

    /// <summary>
    /// Gets the SHA-256 hash of the explicit trust material.
    /// </summary>
    public ReadOnlyMemory<byte> ExplicitTrustMaterialSha256 { get; }

    /// <summary>
    /// Gets a value that indicates whether an exact peer identity has been captured.
    /// </summary>
    public bool HasExactPeerIdentity => !ExactPeerLeafCertificateDer.IsEmpty;

    /// <summary>
    /// Gets a value that indicates whether explicit trust material has been captured.
    /// </summary>
    public bool HasExplicitTrustMaterial => !ExplicitTrustMaterialSha256.IsEmpty;

    /// <summary>
    /// Gets a value that indicates whether the snapshot is ready for policy evaluation.
    /// </summary>
    public bool IsComplete => HasExactPeerIdentity && HasExplicitTrustMaterial;

    /// <summary>
    /// Copies caller-provided bytes so the snapshot remains immutable after construction.
    /// </summary>
    private static ReadOnlyMemory<byte> CloneBytes(ReadOnlyMemory<byte> bytes)
    {
        return bytes.IsEmpty ? ReadOnlyMemory<byte>.Empty : bytes.ToArray();
    }
}
