namespace Incursa.Qpack;

/// <summary>
/// Contains an encoded QPACK field section and any encoder-stream bytes that preceded it.
/// </summary>
public sealed class QPackFieldSectionEncodeResult
{
    internal QPackFieldSectionEncodeResult(byte[] encodedFieldSection, byte[] encoderStreamInstructions, ulong requiredInsertCount)
    {
        EncodedFieldSection = encodedFieldSection;
        EncoderStreamInstructions = encoderStreamInstructions;
        RequiredInsertCount = requiredInsertCount;
    }

    /// <summary>
    /// Gets the encoded field section bytes.
    /// </summary>
    public byte[] EncodedFieldSection { get; }

    /// <summary>
    /// Gets encoder-stream instructions generated before the field section.
    /// </summary>
    public byte[] EncoderStreamInstructions { get; }

    /// <summary>
    /// Gets the Required Insert Count for the field section.
    /// </summary>
    public ulong RequiredInsertCount { get; }
}
