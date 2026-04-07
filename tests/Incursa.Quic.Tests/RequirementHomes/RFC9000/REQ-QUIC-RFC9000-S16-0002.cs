namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0002">The integer value MUST be encoded on the remaining bits, in network byte order.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S16-0002")]
public sealed class REQ_QUIC_RFC9000_S16_0002
{
    public static TheoryData<byte[], ulong, int> ExactParseCases => new()
    {
        { new byte[] { 0x00 }, 0UL, 1 },
        { new byte[] { 0x3F }, 63UL, 1 },
        { new byte[] { 0x40, 0x40 }, 64UL, 2 },
        { new byte[] { 0x7F, 0xFF }, 16_383UL, 2 },
        { new byte[] { 0x80, 0x00, 0x40, 0x00 }, 16_384UL, 4 },
        { new byte[] { 0x92, 0x34, 0x56, 0x78 }, 0x1234_5678UL, 4 },
        { new byte[] { 0xBF, 0xFF, 0xFF, 0xFF }, 1_073_741_823UL, 4 },
        { new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 }, 1_073_741_824UL, 8 },
        { new byte[] { 0xC1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF }, 0x0123_4567_89AB_CDEFUL, 8 },
        { new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, QuicVariableLengthInteger.MaxValue, 8 },
    };

    public static TheoryData<ulong, byte[]> ExactFormatCases => new()
    {
        { 0UL, new byte[] { 0x00 } },
        { 63UL, new byte[] { 0x3F } },
        { 64UL, new byte[] { 0x40, 0x40 } },
        { 16_383UL, new byte[] { 0x7F, 0xFF } },
        { 16_384UL, new byte[] { 0x80, 0x00, 0x40, 0x00 } },
        { 0x1234_5678UL, new byte[] { 0x92, 0x34, 0x56, 0x78 } },
        { 1_073_741_823UL, new byte[] { 0xBF, 0xFF, 0xFF, 0xFF } },
        { 1_073_741_824UL, new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00 } },
        { 0x0123_4567_89AB_CDEFUL, new byte[] { 0xC1, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF } },
        { QuicVariableLengthInteger.MaxValue, new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } },
    };

    [Theory]
    [MemberData(nameof(ExactParseCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParse_DecodesExactWireEncodings(byte[] encoded, ulong expectedValue, int expectedLength)
    {
        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(expectedValue, parsed);
        Assert.Equal(expectedLength, bytesConsumed);
    }

    [Theory]
    [MemberData(nameof(ExactFormatCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormat_WritesExactWireEncodings(ulong value, byte[] expectedEncoding)
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.Equal(expectedEncoding.Length, bytesWritten);
        Assert.True(expectedEncoding.AsSpan().SequenceEqual(buffer[..bytesWritten]));
    }
}
