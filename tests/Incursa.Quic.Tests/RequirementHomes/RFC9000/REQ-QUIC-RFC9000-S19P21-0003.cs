// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0003">This allows for efficient encoding of frames, but it means that an endpoint MUST NOT send a frame of a type that is unknown to its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P21-0003")]
public sealed class REQ_QUIC_RFC9000_S19P21_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0003">This allows for efficient encoding of frames, but it means that an endpoint MUST NOT send a frame of a type that is unknown to its peer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P21-0003")]
    public void TryFormatStreamFrame_UsesKnownFrameTypeValues()
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x0C, 0x04, 0, [0xAA], destination, out int bytesWritten));
        Assert.True(QuicVariableLengthInteger.TryParse(destination[..bytesWritten], out ulong frameType, out int bytesConsumed));
        Assert.Equal(0x0CUL, frameType);
        Assert.Equal(1, bytesConsumed);

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x08, 0x04, 0, [0xAA], destination, out int lowBytesWritten));
        Assert.True(QuicVariableLengthInteger.TryParse(destination[..lowBytesWritten], out ulong lowFrameType, out int lowBytesConsumed));
        Assert.Equal(0x08UL, lowFrameType);
        Assert.Equal(1, lowBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0003">This allows for efficient encoding of frames, but it means that an endpoint MUST NOT send a frame of a type that is unknown to its peer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P21-0003")]
    public void TryFormatStreamFrame_PreservesTheBoundaryDefinedTypes()
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x08, 0x04, 0, [], destination, out int lowBytesWritten));
        Assert.True(QuicVariableLengthInteger.TryParse(destination[..lowBytesWritten], out ulong lowFrameType, out int lowBytesConsumed));
        Assert.Equal(0x08UL, lowFrameType);
        Assert.Equal(1, lowBytesConsumed);

        Assert.True(QuicFrameCodec.TryFormatStreamFrame(0x0F, 0x04, 0, [], destination, out int highBytesWritten));
        Assert.True(QuicVariableLengthInteger.TryParse(destination[..highBytesWritten], out ulong highFrameType, out int highBytesConsumed));
        Assert.Equal(0x0FUL, highFrameType);
        Assert.Equal(1, highBytesConsumed);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P21-0003">This allows for efficient encoding of frames, but it means that an endpoint MUST NOT send a frame of a type that is unknown to its peer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P21-0003")]
    public void TryFormatStreamFrame_RejectsUnknownFrameTypeValues()
    {
        Span<byte> destination = stackalloc byte[32];

        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x07, 0x04, 0, [0xAA], destination, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamFrame(0x10, 0x04, 0, [0xAA], destination, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S19P21-0003")]
    public void TryFormatStreamFrame_FuzzAcceptsOnlyKnownStreamFrameTypeValues()
    {
        byte[] destination = new byte[64];
        byte[] streamData = [0xAA, 0xBB];

        for (byte frameType = 0x00; frameType <= 0x12; frameType++)
        {
            bool formatted = QuicFrameCodec.TryFormatStreamFrame(
                frameType,
                streamId: 0x04,
                offset: 0,
                streamData,
                destination,
                out int bytesWritten);
            bool knownStreamType = frameType is >= 0x08 and <= 0x0F;

            Assert.Equal(knownStreamType, formatted);
            if (knownStreamType)
            {
                Assert.True(QuicVariableLengthInteger.TryParse(destination.AsSpan(0, bytesWritten), out ulong parsedFrameType, out _));
                Assert.Equal(frameType, parsedFrameType);
            }
        }
    }
}
