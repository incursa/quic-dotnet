// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: The managed client policy floor is exact-match only, so the policy stores immutable
// byte snapshots of the peer leaf certificate and explicit trust material.
// SEE: QuicClientCertificatePolicySnapshot
/// <summary>
/// Exact peer-certificate inputs for the narrow managed client certificate-policy floor.
/// </summary>
public sealed class QuicPeerCertificatePolicy
{
    private ReadOnlyMemory<byte> exactPeerLeafCertificateDer;
    private ReadOnlyMemory<byte> explicitTrustMaterialSha256;

    /// <summary>
    /// Gets the exact peer leaf certificate DER bytes to match.
    /// </summary>
    public ReadOnlyMemory<byte> ExactPeerLeafCertificateDer
    {
        get => exactPeerLeafCertificateDer;
        init => exactPeerLeafCertificateDer = CloneBytes(value);
    }

    /// <summary>
    /// Gets the explicit trust-material SHA-256 bytes to match.
    /// </summary>
    public ReadOnlyMemory<byte> ExplicitTrustMaterialSha256
    {
        get => explicitTrustMaterialSha256;
        init => explicitTrustMaterialSha256 = CloneBytes(value);
    }

    private static ReadOnlyMemory<byte> CloneBytes(ReadOnlyMemory<byte> bytes)
    {
        return bytes.IsEmpty ? ReadOnlyMemory<byte>.Empty : bytes.ToArray();
    }
}
