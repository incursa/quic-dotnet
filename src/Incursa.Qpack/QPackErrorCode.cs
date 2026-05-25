namespace Incursa.Qpack;

/// <summary>
/// QPACK error codes registered by RFC 9204 for HTTP/3.
/// </summary>
public enum QPackErrorCode : long
{
    /// <summary>
    /// Decoding of a field section failed.
    /// </summary>
    DecompressionFailed = 0x0200,

    /// <summary>
    /// Decoding of the encoder stream failed.
    /// </summary>
    EncoderStreamError = 0x0201,

    /// <summary>
    /// Decoding of the decoder stream failed.
    /// </summary>
    DecoderStreamError = 0x0202,
}
