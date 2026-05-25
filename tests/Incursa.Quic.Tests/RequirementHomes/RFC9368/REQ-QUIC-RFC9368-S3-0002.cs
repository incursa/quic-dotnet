using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9368-S3-0002")]
public sealed class REQ_QUIC_RFC9368_S3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_AcceptsAValidVersionInformationPayload()
    {
        QuicTransportParameters parameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1]);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.VersionInformation);
        AssertVersionInformationEqual(parameters.VersionInformation!, parsed.VersionInformation!);
    }

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

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_RejectsClientSentVersionInformationWithoutChosenVersionInAvailableVersions()
    {
        byte[] encoded = BuildVersionInformationBlock(
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.Version1,
            QuicVersionNegotiation.CreateReservedVersion(0x10203040));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseTransportParameters_RejectsVersionInformationWithMisalignedLength()
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x11,
                [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Server,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryParseTransportParameters_RejectsMalformedVersionInformationAcrossRepresentativeShapes()
    {
        QuicVersionInformationFuzzSupport.FuzzTransportParameterCodecRejectsMalformedVersionInformationAcrossRepresentativeShapes();
    }

    private static QuicTransportParameters CreateVersionInformationTransportParameters(
        uint chosenVersion,
        uint[] availableVersions)
    {
        return new QuicTransportParameters
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = chosenVersion,
                AvailableVersions = availableVersions,
            },
        };
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

    private static void AssertVersionInformationEqual(QuicVersionInformation expected, QuicVersionInformation actual)
    {
        Assert.Equal(expected.ChosenVersion, actual.ChosenVersion);
        Assert.True(expected.AvailableVersions.AsSpan().SequenceEqual(actual.AvailableVersions));
    }
}
