// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S10-3-1-P1-S1-R01">An endpoint MUST detect a potential Stateless Reset using the trailing 16 bytes of the UDP datagram.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S10-3-1-P1-S1-R01")]
public sealed class RFC9000_S10_3_1_P1_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [Requirement("RFC9000-S10-3-1-P1-S1-R01")]
    public void MatchesAnyStatelessResetToken_DoesNotUseEarlierSixteenBytesAsTheToken()
    {
        byte[] earlierToken = QuicStatelessResetRequirementTestData.CreateToken(0x40);
        byte[] trailingToken = QuicStatelessResetRequirementTestData.CreateToken(0x80);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(
            trailingToken,
            datagramLength: QuicStatelessReset.MinimumDatagramLength + earlierToken.Length);

        earlierToken.CopyTo(datagram.AsSpan(1));

        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> parsedTrailingToken));
        Assert.True(trailingToken.AsSpan().SequenceEqual(parsedTrailingToken));
        Assert.False(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, earlierToken));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryGetTrailingStatelessResetToken_DetectsPotentialResetUsingTheTrailingSixteenBytes()
    {
        byte[] token = QuicStatelessResetRequirementTestData.CreateToken(0x40);

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token);

        Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
        Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken));
        Assert.True(token.AsSpan().SequenceEqual(trailingToken));
    }
}
