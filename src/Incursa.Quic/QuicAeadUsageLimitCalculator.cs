namespace Incursa.Quic;

/// <summary>
/// Provides Appendix B AEAD packet-use limits for the AEADs and packet-size profiles modeled in this library.
/// </summary>
public static class QuicAeadUsageLimitCalculator
{
    private const double AeadUsageLimitBase = 2d;
    private const double GcmConfidentialityLimitExponentStrictlyLimitedToTwoPow11Bytes = 28d;
    private const double GcmConfidentialityLimitExponentAllowsPacketsAsLargeAsTwoPow16Bytes = 23d;
    private const double GcmIntegrityLimitExponentStrictlyLimitedToTwoPow11Bytes = 57d;
    private const double GcmIntegrityLimitExponentUnrestricted = 52d;
    private const double CcmUsageLimitExponentStrictlyLimitedToTwoPow11Bytes = 26.5d;
    private const double CcmUsageLimitExponentUnrestricted = 21.5d;

    /// <summary>
    /// Computes the Appendix B confidentiality and integrity limits for the supplied AEAD and packet-size profiles.
    /// </summary>
    /// <remarks>
    /// The selected packet-size profiles are intentionally narrow. They model the Appendix B guidance that is
    /// exercised by the repository's RFC 9001 requirements, not a full generic AEAD policy engine.
    /// </remarks>
    public static bool TryGetUsageLimits(
        QuicAeadAlgorithm algorithm,
        QuicAeadPacketSizeProfile confidentialityPacketSizeProfile,
        QuicAeadPacketSizeProfile integrityPacketSizeProfile,
        out QuicAeadUsageLimits limits)
    {
        limits = default;

        return algorithm switch
        {
            QuicAeadAlgorithm.Aes128Gcm or QuicAeadAlgorithm.Aes256Gcm => TryGetGcmUsageLimits(
                confidentialityPacketSizeProfile,
                integrityPacketSizeProfile,
                out limits),
            QuicAeadAlgorithm.Aes128Ccm => TryGetCcmUsageLimits(
                confidentialityPacketSizeProfile,
                integrityPacketSizeProfile,
                out limits),
            _ => false,
        };
    }

    private static bool TryGetGcmUsageLimits(
        QuicAeadPacketSizeProfile confidentialityPacketSizeProfile,
        QuicAeadPacketSizeProfile integrityPacketSizeProfile,
        out QuicAeadUsageLimits limits)
    {
        limits = default;

        if (!TryGetGcmConfidentialityLimitPackets(confidentialityPacketSizeProfile, out double confidentialityLimitPackets))
        {
            return false;
        }

        if (!TryGetGcmIntegrityLimitPackets(integrityPacketSizeProfile, out double integrityLimitPackets))
        {
            return false;
        }

        limits = new QuicAeadUsageLimits(confidentialityLimitPackets, integrityLimitPackets);
        return true;
    }

    private static bool TryGetCcmUsageLimits(
        QuicAeadPacketSizeProfile confidentialityPacketSizeProfile,
        QuicAeadPacketSizeProfile integrityPacketSizeProfile,
        out QuicAeadUsageLimits limits)
    {
        limits = default;

        if (confidentialityPacketSizeProfile != integrityPacketSizeProfile)
        {
            return false;
        }

        return confidentialityPacketSizeProfile switch
        {
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes => CreateUsageLimits(
                Math.Pow(AeadUsageLimitBase, CcmUsageLimitExponentStrictlyLimitedToTwoPow11Bytes),
                Math.Pow(AeadUsageLimitBase, CcmUsageLimitExponentStrictlyLimitedToTwoPow11Bytes),
                out limits),
            QuicAeadPacketSizeProfile.Unrestricted => CreateUsageLimits(
                Math.Pow(AeadUsageLimitBase, CcmUsageLimitExponentUnrestricted),
                Math.Pow(AeadUsageLimitBase, CcmUsageLimitExponentUnrestricted),
                out limits),
            _ => false,
        };
    }

    private static bool TryGetGcmConfidentialityLimitPackets(
        QuicAeadPacketSizeProfile packetSizeProfile,
        out double limitPackets)
    {
        limitPackets = default;

        return packetSizeProfile switch
        {
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes => CreateLimitPackets(Math.Pow(AeadUsageLimitBase, GcmConfidentialityLimitExponentStrictlyLimitedToTwoPow11Bytes), out limitPackets),
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes => CreateLimitPackets(Math.Pow(AeadUsageLimitBase, GcmConfidentialityLimitExponentAllowsPacketsAsLargeAsTwoPow16Bytes), out limitPackets),
            _ => false,
        };
    }

    private static bool TryGetGcmIntegrityLimitPackets(
        QuicAeadPacketSizeProfile packetSizeProfile,
        out double limitPackets)
    {
        limitPackets = default;

        return packetSizeProfile switch
        {
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes => CreateLimitPackets(Math.Pow(AeadUsageLimitBase, GcmIntegrityLimitExponentStrictlyLimitedToTwoPow11Bytes), out limitPackets),
            QuicAeadPacketSizeProfile.Unrestricted => CreateLimitPackets(Math.Pow(AeadUsageLimitBase, GcmIntegrityLimitExponentUnrestricted), out limitPackets),
            _ => false,
        };
    }

    private static bool CreateUsageLimits(double confidentialityLimitPackets, double integrityLimitPackets, out QuicAeadUsageLimits limits)
    {
        limits = new QuicAeadUsageLimits(confidentialityLimitPackets, integrityLimitPackets);
        return true;
    }

    private static bool CreateLimitPackets(double limitPackets, out double assignedLimitPackets)
    {
        assignedLimitPackets = limitPackets;
        return true;
    }
}
