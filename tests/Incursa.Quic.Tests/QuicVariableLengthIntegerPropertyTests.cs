using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

public sealed class QuicVariableLengthIntegerPropertyTests
{
    [Property(Arbitrary = new[] { typeof(QuicVariableLengthIntegerPropertyGenerators) })]
    [Trait("Requirement", "REQ-QUIC-VINT-0001")]
    [Trait("Requirement", "REQ-QUIC-VINT-0002")]
    [Trait("Requirement", "REQ-QUIC-VINT-0003")]
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
