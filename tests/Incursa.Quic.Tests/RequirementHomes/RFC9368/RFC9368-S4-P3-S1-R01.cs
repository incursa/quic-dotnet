// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("RFC9368-S4-P3-S1-R01")]
public sealed class RFC9368_S4_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_AcceptsPeerVersionInformationPayload()
    {
        QuicVersionInformation expected = new()
        {
            ChosenVersion = QuicVersionNegotiation.Version2,
            AvailableVersions =
            [
                QuicVersionNegotiation.Version2,
                QuicVersionNegotiation.Version1,
            ],
        };

        byte[] encoded = BuildVersionInformationBlock(
            expected.ChosenVersion,
            expected.AvailableVersions);

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.VersionInformation);
        AssertVersionInformationEqual(expected, parsed.VersionInformation!);
    }

    private static byte[] BuildVersionInformationBlock(
        uint chosenVersion,
        ReadOnlySpan<uint> availableVersions)
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

    private static void AssertVersionInformationEqual(QuicVersionInformation expected, QuicVersionInformation actual)
    {
        Assert.Equal(expected.ChosenVersion, actual.ChosenVersion);
        Assert.True(expected.AvailableVersions.AsSpan().SequenceEqual(actual.AvailableVersions));
    }
}
