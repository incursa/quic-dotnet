namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0004">Values MUST NOT need to be encoded on the minimum number of bytes necessary, with the sole exception of the Frame Type field; see Section 12.4.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S16-0004")]
public sealed class REQ_QUIC_RFC9000_S16_0004
{
    public static TheoryData<ulong, int> NonMinimalEncodingCases => new()
    {
        { 0UL, 2 },
        { 1UL, 4 },
        { 63UL, 8 },
    };

    [Theory]
    [MemberData(nameof(NonMinimalEncodingCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParse_AcceptsNonMinimalEncodings(ulong value, int encodedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

        Assert.True(QuicVarintTestData.EncodeMinimal(value).Length < encodedLength);
        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(encodedLength, bytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParse_RejectsEmptyInput()
    {
        Assert.False(QuicVariableLengthInteger.TryParse(Array.Empty<byte>(), out _, out _));
    }

    [Theory]
    [InlineData(new byte[] { 0x40 })]
    [InlineData(new byte[] { 0x80, 0x00, 0x00 })]
    [InlineData(new byte[] { 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParse_RejectsTruncatedInputs(byte[] encoded)
    {
        Assert.False(QuicVariableLengthInteger.TryParse(encoded, out _, out _));
    }

    [Theory]
    [MemberData(nameof(NonMinimalEncodingCases))]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParse_RejectsTruncatedNonMinimalEncodings(ulong value, int encodedLength)
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(value, encodedLength);

        Assert.False(QuicVariableLengthInteger.TryParse(encoded[..^1], out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParse_AcceptsZeroEncodedOnEightBytes()
    {
        byte[] encoded = QuicVarintTestData.EncodeWithLength(0UL, 8);

        Assert.True(QuicVariableLengthInteger.TryParse(encoded, out ulong parsed, out int bytesConsumed));
        Assert.Equal(0UL, parsed);
        Assert.Equal(8, bytesConsumed);
    }
}
