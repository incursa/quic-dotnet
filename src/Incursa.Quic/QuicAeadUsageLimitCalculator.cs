namespace Incursa.Quic;

/// <summary>
/// Provides Appendix B AEAD packet-use limits for the AEADs and packet-size profiles modeled in this library.
/// </summary>
public static class QuicAeadUsageLimitCalculator
{
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
                Math.Pow(2d, 26.5d),
                Math.Pow(2d, 26.5d),
                out limits),
            QuicAeadPacketSizeProfile.Unrestricted => CreateUsageLimits(
                Math.Pow(2d, 21.5d),
                Math.Pow(2d, 21.5d),
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
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes => CreateLimitPackets(Math.Pow(2d, 28d), out limitPackets),
            QuicAeadPacketSizeProfile.AllowsPacketsAsLargeAsTwoPow16Bytes => CreateLimitPackets(Math.Pow(2d, 23d), out limitPackets),
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
            QuicAeadPacketSizeProfile.StrictlyLimitedToTwoPow11Bytes => CreateLimitPackets(Math.Pow(2d, 57d), out limitPackets),
            QuicAeadPacketSizeProfile.Unrestricted => CreateLimitPackets(Math.Pow(2d, 52d), out limitPackets),
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
