namespace Incursa.Quic;

/// <summary>
/// Describes TLS-derived packet-protection material for a non-Initial encryption level.
/// </summary>
internal readonly struct QuicTlsPacketProtectionMaterial
{
    private readonly byte[] aeadKey;
    private readonly byte[] aeadIv;
    private readonly byte[] headerProtectionKey;

    private QuicTlsPacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        QuicAeadAlgorithm algorithm,
        QuicAeadUsageLimits usageLimits,
        byte[] aeadKey,
        byte[] aeadIv,
        byte[] headerProtectionKey)
    {
        EncryptionLevel = encryptionLevel;
        Algorithm = algorithm;
        UsageLimits = usageLimits;
        this.aeadKey = aeadKey;
        this.aeadIv = aeadIv;
        this.headerProtectionKey = headerProtectionKey;
    }

    /// <summary>
    /// Gets the encryption level this material applies to.
    /// </summary>
    public QuicTlsEncryptionLevel EncryptionLevel { get; }

    /// <summary>
    /// Gets the AEAD algorithm bound to the material.
    /// </summary>
    public QuicAeadAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the usage-limit metadata associated with the material.
    /// </summary>
    public QuicAeadUsageLimits UsageLimits { get; }

    /// <summary>
    /// Gets the AEAD key.
    /// </summary>
    public ReadOnlySpan<byte> AeadKey => aeadKey;

    /// <summary>
    /// Gets the AEAD IV.
    /// </summary>
    public ReadOnlySpan<byte> AeadIv => aeadIv;

    /// <summary>
    /// Gets the header-protection key.
    /// </summary>
    public ReadOnlySpan<byte> HeaderProtectionKey => headerProtectionKey;

    internal byte[] AeadKeyBytes => aeadKey;

    internal byte[] AeadIvBytes => aeadIv;

    internal byte[] HeaderProtectionKeyBytes => headerProtectionKey;

    /// <summary>
    /// Creates a validated packet-protection material package.
    /// </summary>
    internal static bool TryCreate(
        QuicTlsEncryptionLevel encryptionLevel,
        QuicAeadAlgorithm algorithm,
        ReadOnlySpan<byte> aeadKey,
        ReadOnlySpan<byte> aeadIv,
        ReadOnlySpan<byte> headerProtectionKey,
        QuicAeadUsageLimits usageLimits,
        out QuicTlsPacketProtectionMaterial material)
    {
        material = default;

        if (encryptionLevel is not (QuicTlsEncryptionLevel.Handshake or QuicTlsEncryptionLevel.OneRtt))
        {
            return false;
        }

        if (!QuicAeadAlgorithmMetadata.TryGetPacketProtectionLengths(
            algorithm,
            out int expectedAeadKeyLength,
            out int expectedAeadIvLength,
            out int expectedHeaderProtectionKeyLength))
        {
            return false;
        }

        if (aeadKey.Length != expectedAeadKeyLength
            || aeadIv.Length != expectedAeadIvLength
            || headerProtectionKey.Length != expectedHeaderProtectionKeyLength)
        {
            return false;
        }

        if (!TryValidateUsageLimits(usageLimits))
        {
            return false;
        }

        material = new QuicTlsPacketProtectionMaterial(
            encryptionLevel,
            algorithm,
            usageLimits,
            aeadKey.ToArray(),
            aeadIv.ToArray(),
            headerProtectionKey.ToArray());
        return true;
    }

    /// <summary>
    /// Checks whether the material matches another material package byte-for-byte.
    /// </summary>
    internal bool Matches(in QuicTlsPacketProtectionMaterial other)
    {
        return EncryptionLevel == other.EncryptionLevel
            && Algorithm == other.Algorithm
            && BitConverter.DoubleToInt64Bits(UsageLimits.ConfidentialityLimitPackets) == BitConverter.DoubleToInt64Bits(other.UsageLimits.ConfidentialityLimitPackets)
            && BitConverter.DoubleToInt64Bits(UsageLimits.IntegrityLimitPackets) == BitConverter.DoubleToInt64Bits(other.UsageLimits.IntegrityLimitPackets)
            && AeadKey.SequenceEqual(other.AeadKey)
            && AeadIv.SequenceEqual(other.AeadIv)
            && HeaderProtectionKey.SequenceEqual(other.HeaderProtectionKey);
    }

    private static bool TryValidateUsageLimits(QuicAeadUsageLimits usageLimits)
    {
        return IsPositiveFinite(usageLimits.ConfidentialityLimitPackets)
            && IsPositiveFinite(usageLimits.IntegrityLimitPackets);
    }

    private static bool IsPositiveFinite(double value)
    {
        return double.IsFinite(value) && value > 0;
    }
}
