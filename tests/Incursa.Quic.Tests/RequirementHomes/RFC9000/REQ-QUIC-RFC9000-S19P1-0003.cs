// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P1-0003")]
public sealed class REQ_QUIC_RFC9000_S19P1_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatVersion1InitialDatagramPadding_WritesTheMinimumPaddingNeededForAnInitialPacket()
    {
        Span<byte> destination = stackalloc byte[13];

        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1187, destination, out int bytesWritten));
        Assert.Equal(13, bytesWritten);
        Assert.All(destination[..bytesWritten].ToArray(), static value => Assert.Equal(0, value));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-0856")]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndTooSmallDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("REQ-QUIC-RFC9000-0856")]
    public void TryGetVersion1InitialDatagramPaddingLength_ReturnsZeroAtTheMinimumSizeBoundary()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1200, out int paddingLength));
        Assert.Equal(0, paddingLength);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryFormatVersion1InitialDatagramPadding_FuzzPadsInitialPacketsToTheMinimumSize()
    {
        int[] currentPayloadLengths = [0, 1, 100, 1_187, 1_199, 1_200, 1_250];

        foreach (int currentPayloadLength in currentPayloadLengths)
        {
            Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
                currentPayloadLength,
                out int paddingLength));
            Assert.Equal(Math.Max(0, 1_200 - currentPayloadLength), paddingLength);

            byte[] destination = new byte[paddingLength];
            Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
                currentPayloadLength,
                destination,
                out int bytesWritten));
            Assert.Equal(paddingLength, bytesWritten);
            Assert.All(destination, static value => Assert.Equal(0x00, value));
        }
    }
}
