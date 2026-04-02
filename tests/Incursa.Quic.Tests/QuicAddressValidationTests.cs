namespace Incursa.Quic.Tests;

public sealed class QuicAddressValidationTests
{
    [Theory]
    [InlineData(true, 8, true)]
    [InlineData(true, 7, false)]
    [InlineData(false, 8, false)]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0001")]
    [Trait("Category", "Positive")]
    public void CanConsiderPeerAddressValidated_RequiresEndpointChosenAndAtLeast64BitsOfEntropy(
        bool chosenByEndpoint,
        int connectionIdLength,
        bool expected)
    {
        byte[] connectionId = Enumerable.Range(0, connectionIdLength).Select(index => (byte)index).ToArray();

        Assert.Equal(expected, QuicAddressValidation.CanConsiderPeerAddressValidated(connectionId, chosenByEndpoint));
    }

    [Theory]
    [InlineData(1187, 13)]
    [InlineData(1199, 1)]
    [InlineData(1200, 0)]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [Trait("Category", "Positive")]
    public void TryGetVersion1InitialDatagramPaddingLength_ComputesTheRemainingPadding(
        int currentPayloadLength,
        int expectedPaddingLength)
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
            currentPayloadLength,
            out int paddingLength));

        Assert.Equal(expectedPaddingLength, paddingLength);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [Trait("Category", "Negative")]
    public void TryGetVersion1InitialDatagramPaddingLength_RejectsNegativeCurrentPayloadLength()
    {
        Assert.False(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(-1, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [Trait("Category", "Positive")]
    public void TryFormatVersion1InitialDatagramPadding_WritesRepeatedPaddingFrames()
    {
        Span<byte> destination = stackalloc byte[13];

        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            1187,
            destination,
            out int bytesWritten));

        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));

        for (int index = 0; index < bytesWritten; index++)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(destination[index..bytesWritten], out int bytesConsumed));
            Assert.Equal(1, bytesConsumed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0004")]
    [Trait("Category", "Negative")]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndShortDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }
}
