using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicVariableLengthIntegerPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-VINT-0001" missing="true">Requirement text not found.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-VINT-0002" missing="true">Requirement text not found.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-VINT-0003" missing="true">Requirement text not found.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-VINT-0001")]
    [Requirement("REQ-QUIC-VINT-0002")]
    [Requirement("REQ-QUIC-VINT-0003")]
    [Trait("Category", "Property")]
    public void TryFormatAndParse_RoundTripsRepresentableValues(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];

        Assert.True(QuicVariableLengthInteger.TryFormat(value, buffer, out int bytesWritten));
        Assert.True(QuicVariableLengthInteger.TryParse(buffer[..bytesWritten], out ulong parsed, out int bytesConsumed));
        Assert.Equal(value, parsed);
        Assert.Equal(bytesWritten, bytesConsumed);
    }
}
