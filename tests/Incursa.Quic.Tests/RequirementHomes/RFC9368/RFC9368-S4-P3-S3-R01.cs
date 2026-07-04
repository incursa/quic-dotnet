// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("RFC9368-S4-P3-S3-R01")]
public sealed class RFC9368_S4_P3_S3_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsVersionInformationWithZeroChosenVersion()
    {
        byte[] encoded = BuildVersionInformationBlock(
            0,
            QuicVersionNegotiation.Version1);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsVersionInformationWithZeroAvailableVersion()
    {
        byte[] encoded = BuildVersionInformationBlock(
            QuicVersionNegotiation.Version1,
            0);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    private static byte[] BuildVersionInformationBlock(
        uint chosenVersion,
        params uint[] availableVersions)
    {
        byte[] versionInformationValue = new byte[sizeof(uint) + (availableVersions.Length * sizeof(uint))];
        BinaryPrimitives.WriteUInt32BigEndian(versionInformationValue, chosenVersion);

        int offset = sizeof(uint);
        for (int index = 0; index < availableVersions.Length; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                versionInformationValue.AsSpan(offset, sizeof(uint)),
                availableVersions[index]);
            offset += sizeof(uint);
        }

        return QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x11, versionInformationValue));
    }
}
