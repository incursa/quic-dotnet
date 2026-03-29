namespace Incursa.Quic;

/// <summary>
/// A parsed or constructed CRYPTO frame.
/// </summary>
public readonly ref struct QuicCryptoFrame
{
    private readonly ulong offset;
    private readonly ReadOnlySpan<byte> cryptoData;

    /// <summary>
    /// Initializes a CRYPTO frame view.
    /// </summary>
    public QuicCryptoFrame(ulong offset, ReadOnlySpan<byte> cryptoData)
    {
        this.offset = offset;
        this.cryptoData = cryptoData;
    }

    /// <summary>
    /// Gets the crypto stream offset.
    /// </summary>
    public ulong Offset => offset;

    /// <summary>
    /// Gets the CRYPTO data bytes.
    /// </summary>
    public ReadOnlySpan<byte> CryptoData => cryptoData;
}
