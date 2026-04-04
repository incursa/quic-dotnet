namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S16-0003">This means that integers are encoded on 1, 2, 4, or 8 bytes and MAY encode 6-, 14-, 30-, or 62-bit values, respectively.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S16-0003")]
public sealed class REQ_QUIC_RFC9000_S16_0003
{
    public static TheoryData<ulong, int> LengthClassCases => new()
    {
        { 0UL, 1 },
        { 63UL, 1 },
        { 64UL, 2 },
        { 16_383UL, 2 },
        { 16_384UL, 4 },
        { 1_073_741_823UL, 4 },
        { 1_073_741_824UL, 8 },
        { QuicVariableLengthInteger.MaxValue, 8 },
    };

    [Theory]
    [MemberData(nameof(LengthClassCases))]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormat_UsesTheExpectedLengthForEachValueClass(ulong value, int expectedLength)
    {
        byte[] buffer = new byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.Equal(expectedLength, bytesWritten);
        Assert.True(QuicVariableLengthInteger.TryParse(buffer[..bytesWritten], out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(expectedLength, bytesConsumed);
    }
}
