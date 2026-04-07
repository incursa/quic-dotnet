namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0001">The QUIC variable-length integer encoding MUST reserve the two most significant bits of the first byte to encode the base-2 logarithm of the integer encoding length in bytes.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S16-0001")]
public sealed class REQ_QUIC_RFC9000_S16_0001
{
    public static TheoryData<ulong, byte> LengthPrefixCases => new()
    {
        { 0UL, 0x00 },
        { 63UL, 0x00 },
        { 64UL, 0x40 },
        { 16_383UL, 0x40 },
        { 16_384UL, 0x80 },
        { 1_073_741_823UL, 0x80 },
        { 1_073_741_824UL, 0xC0 },
        { QuicVariableLengthInteger.MaxValue, 0xC0 },
    };

    [Theory]
    [MemberData(nameof(LengthPrefixCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormat_SetsTheExpectedLengthPrefixBits(ulong value, byte expectedPrefix)
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.Equal(expectedPrefix, (byte)(buffer[0] & 0xC0));
        Assert.True(QuicVariableLengthInteger.TryParse(buffer[..bytesWritten], out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(bytesWritten, bytesConsumed);
    }
}
