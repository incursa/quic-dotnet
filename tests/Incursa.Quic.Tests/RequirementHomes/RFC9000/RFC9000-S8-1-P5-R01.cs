// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S8-1-P5-R01">Clients MUST ensure that UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes, adding PADDING frames as necessary.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S8-1-P5-R01")]
public sealed class REQ_QUIC_RFC9000_0375
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryGetVersion1InitialDatagramPaddingLength_UsesTheExactMinimumPayloadBoundary()
    {
        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(1200, out int paddingLength));

        Assert.Equal(0, paddingLength);
    }

    [Theory]
    [InlineData(1187, 13)]
    [InlineData(1199, 1)]
    [InlineData(1200, 0)]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
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
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryGetVersion1InitialDatagramPaddingLength_RejectsNegativeCurrentPayloadLength()
    {
        Assert.False(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(-1, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatVersion1InitialDatagramPadding_RejectsNegativeLengthsAndShortDestinations()
    {
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(-1, stackalloc byte[1], out _));
        Assert.False(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(1199, stackalloc byte[0], out _));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(37)]
    [InlineData(997)]
    [InlineData(1199)]
    [InlineData(1200)]
    [Requirement("REQ-QUIC-RFC9000-S8P1-0006")]
    [Requirement("RFC9000-S8-1-P5-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryFormatVersion1InitialDatagramPaddingPadsInitialPayloadsToTheMinimum(
        int currentPayloadLength)
    {
        int expectedPaddingLength = Math.Max(
            0,
            QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - currentPayloadLength);
        Span<byte> padding = stackalloc byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(QuicAddressValidation.TryGetVersion1InitialDatagramPaddingLength(
            currentPayloadLength,
            out int paddingLength));
        Assert.Equal(expectedPaddingLength, paddingLength);
        Assert.True(QuicAddressValidation.TryFormatVersion1InitialDatagramPadding(
            currentPayloadLength,
            padding,
            out int bytesWritten));

        Assert.Equal(expectedPaddingLength, bytesWritten);
        Assert.Equal(
            Math.Max(currentPayloadLength, QuicVersionNegotiation.Version1MinimumDatagramPayloadSize),
            currentPayloadLength + bytesWritten);
        Assert.All(padding[..bytesWritten].ToArray(), paddingByte => Assert.Equal(0x00, paddingByte));
    }
}
