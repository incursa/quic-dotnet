// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P7-0008")]
public sealed class REQ_QUIC_RFC9000_S19P7_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ParsedDuplicateNewTokenFramesContainTheSameTokenValue()
    {
        byte[] firstEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);
        byte[] duplicateEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out int firstBytesConsumed));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(duplicateEncoded, out QuicNewTokenFrame duplicateParsed, out int duplicateBytesConsumed));

        Assert.Equal(firstEncoded.Length, firstBytesConsumed);
        Assert.Equal(duplicateEncoded.Length, duplicateBytesConsumed);
        Assert.True(firstParsed.Token.SequenceEqual(duplicateParsed.Token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ParsedNewTokenFramesWithDifferentTokenValuesDoNotSatisfyDuplicateRepair()
    {
        byte[] firstEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.RepresentativeToken);
        byte[] differentEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(
            QuicS19P7NewTokenFrameTestSupport.AlternateToken);

        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out _));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(differentEncoded, out QuicNewTokenFrame differentParsed, out _));
        Assert.False(firstParsed.Token.SequenceEqual(differentParsed.Token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ParsedDuplicateNewTokenFramesRemainEqualAcrossDifferentPacketInstances()
    {
        byte[] token = [0x00, 0xFF, 0x40, 0x7F, 0x80, 0x01];
        byte[] originalEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);
        byte[] repairEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token.ToArray());

        Assert.NotSame(originalEncoded, repairEncoded);
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(originalEncoded, out QuicNewTokenFrame originalParsed, out _));
        Assert.True(QuicFrameCodec.TryParseNewTokenFrame(repairEncoded, out QuicNewTokenFrame repairParsed, out _));
        Assert.True(originalParsed.Token.SequenceEqual(repairParsed.Token));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    public void FuzzNewTokenDuplicateRepairKeepsTokenValueStable()
    {
        Random random = new(0x5197_0008);
        for (int iteration = 0; iteration < 64; iteration++)
        {
            byte[] token = new byte[random.Next(1, 32)];
            random.NextBytes(token);
            byte[] firstEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token);
            byte[] duplicateEncoded = QuicS19P7NewTokenFrameTestSupport.BuildNewTokenFrame(token.ToArray());

            Assert.True(QuicFrameCodec.TryParseNewTokenFrame(firstEncoded, out QuicNewTokenFrame firstParsed, out _));
            Assert.True(QuicFrameCodec.TryParseNewTokenFrame(duplicateEncoded, out QuicNewTokenFrame duplicateParsed, out _));
            Assert.True(firstParsed.Token.SequenceEqual(duplicateParsed.Token));
        }
    }
}
