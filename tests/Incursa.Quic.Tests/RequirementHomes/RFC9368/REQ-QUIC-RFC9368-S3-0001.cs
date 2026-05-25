using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9368-S3-0001")]
public sealed class REQ_QUIC_RFC9368_S3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EmitsVersionInformationForClientAndServerSnapshots()
    {
        QuicTransportParameters clientParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1, QuicVersionNegotiation.CreateReservedVersion(0x10203040)]);

        QuicTransportParameters serverParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2]);

        AssertVersionInformationFormatsAsExpected(clientParameters, QuicTransportParameterRole.Client);
        AssertVersionInformationFormatsAsExpected(serverParameters, QuicTransportParameterRole.Server);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_RoundsTripVersionInformationAcrossClientAndServerRoles()
    {
        QuicTransportParameters clientParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version2, QuicVersionNegotiation.Version1, QuicVersionNegotiation.CreateReservedVersion(0x11223344)]);

        QuicTransportParameters serverParameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version1,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2]);

        AssertVersionInformationRoundTrips(
            clientParameters,
            QuicTransportParameterRole.Client,
            QuicTransportParameterRole.Server);

        AssertVersionInformationRoundTrips(
            serverParameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatTransportParameters_EmitsVersionInformationForServerWithAnEmptyAvailableVersionList()
    {
        QuicTransportParameters parameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            []);

        byte[] expected = BuildVersionInformationTuple(
            QuicVersionNegotiation.Version2,
            []);

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_RejectsClientVersionInformationWhenChosenVersionIsMissingFromAvailableVersions()
    {
        QuicTransportParameters parameters = CreateVersionInformationTransportParameters(
            QuicVersionNegotiation.Version2,
            [QuicVersionNegotiation.Version1, QuicVersionNegotiation.CreateReservedVersion(0x10203040)]);

        Span<byte> destination = stackalloc byte[64];
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryFormatTransportParameters_RoundTripsVersionInformationAcrossRepresentativeVersionSets()
    {
        QuicVersionInformationFuzzSupport.FuzzTransportParameterCodecRoundTripsVersionInformationAcrossRepresentativeVersionSets();
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

    private static byte[] BuildVersionInformationTuple(uint chosenVersion, ReadOnlySpan<uint> availableVersions)
    {
        return QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x11,
            BuildVersionInformationValue(chosenVersion, availableVersions));
    }

    private static byte[] BuildVersionInformationValue(uint chosenVersion, ReadOnlySpan<uint> availableVersions)
    {
        byte[] value = new byte[sizeof(uint) + (availableVersions.Length * sizeof(uint))];
        BinaryPrimitives.WriteUInt32BigEndian(value, chosenVersion);

        int offset = sizeof(uint);
        for (int index = 0; index < availableVersions.Length; index++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                value.AsSpan(offset, sizeof(uint)),
                availableVersions[index]);
            offset += sizeof(uint);
        }

        return value;
    }

    private static void AssertVersionInformationFormatsAsExpected(
        QuicTransportParameters parameters,
        QuicTransportParameterRole senderRole)
    {
        byte[] expected = BuildVersionInformationTuple(
            parameters.VersionInformation!.ChosenVersion,
            parameters.VersionInformation.AvailableVersions);

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    private static void AssertVersionInformationRoundTrips(
        QuicTransportParameters parameters,
        QuicTransportParameterRole senderRole,
        QuicTransportParameterRole receiverRole)
    {
        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            senderRole,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            receiverRole,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.VersionInformation);
        Assert.Equal(parameters.VersionInformation!.ChosenVersion, parsed.VersionInformation!.ChosenVersion);
        Assert.True(parameters.VersionInformation.AvailableVersions.AsSpan().SequenceEqual(parsed.VersionInformation.AvailableVersions));
    }
}
