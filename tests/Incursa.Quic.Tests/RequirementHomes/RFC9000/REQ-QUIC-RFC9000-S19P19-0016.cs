// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P19-0016">This MAY be zero length if the sender chooses not to give details beyond the Error Code value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P19-0016")]
public sealed class REQ_QUIC_RFC9000_S19P19_0016
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void TryParseConnectionCloseFrame_AllowsEmptyReasonPhrases(bool isApplicationError)
    {
        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(0x1234, [])
            : new QuicConnectionCloseFrame(0x1234, 0x02, []);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.Equal(0, parsed.ReasonPhrase.Length);
        Assert.Equal(encoded.Length, bytesConsumed);

        Span<byte> destination = stackalloc byte[8];
        Assert.True(QuicFrameCodec.TryFormatConnectionCloseFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseConnectionCloseFrame_DoesNotTreatNonEmptyReasonPhrasesAsZeroLength(bool isApplicationError)
    {
        byte[] reasonPhrase = [0x6F, 0x6B];
        QuicConnectionCloseFrame frame = isApplicationError
            ? new QuicConnectionCloseFrame(0x1234, reasonPhrase)
            : new QuicConnectionCloseFrame(0x1234, 0x02, reasonPhrase);

        byte[] encoded = QuicFrameTestData.BuildConnectionCloseFrame(frame);

        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(encoded, out QuicConnectionCloseFrame parsed, out int bytesConsumed));
        Assert.NotEmpty(parsed.ReasonPhrase.ToArray());
        Assert.Equal(reasonPhrase.Length, parsed.ReasonPhrase.Length);
        Assert.Equal(encoded.Length, bytesConsumed);
    }
}
