// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S8-2-2-P1-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S8P2P2_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S8-2-2-P1-S1-R01">On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing the data contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S8-2-2-P1-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatPathResponseFrame_EchoesChallengeData()
    {
        Span<byte> challengeData = stackalloc byte[QuicPathValidation.PathChallengeDataLength];
        Assert.True(QuicPathValidation.TryGeneratePathChallengeData(challengeData, out int challengeBytesWritten));

        QuicPathResponseFrame frame = new(challengeData[..challengeBytesWritten]);
        Span<byte> encoded = stackalloc byte[16];
        Assert.True(QuicFrameCodec.TryFormatPathResponseFrame(frame, encoded, out int encodedBytesWritten));
        Assert.Equal(9, encodedBytesWritten);

        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(encoded[..encodedBytesWritten], out QuicPathResponseFrame parsed, out int bytesConsumed));
        Assert.Equal(encodedBytesWritten, bytesConsumed);
        Assert.True(challengeData[..challengeBytesWritten].SequenceEqual(parsed.Data));
    }
}
