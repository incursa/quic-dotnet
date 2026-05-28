// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers.Binary;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P1-0006")]
public sealed class REQ_QUIC_RFC9000_S9P6P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerEncryptedExtensionsCarriesPreferredAddressTransportParameter()
    {
        QuicTransportParameters parameters = QuicPreferredAddressRequirementTestSupport.CreateServerTransportParameters();
        byte[] transcript = new byte[512];

        Assert.True(QuicTlsTranscriptProgress.TryFormatDeterministicEncryptedExtensionsTransportParametersMessage(
            parameters,
            QuicTransportParameterRole.Server,
            transcript,
            out int bytesWritten));

        ReadOnlySpan<byte> encryptedExtensions = transcript.AsSpan(0, bytesWritten);
        Assert.Equal((byte)QuicTlsHandshakeMessageType.EncryptedExtensions, encryptedExtensions[0]);

        ReadOnlySpan<byte> transportParameters = GetOnlyTransportParametersExtension(encryptedExtensions);
        Assert.True(TryFindTransportParameter(
            transportParameters,
            QuicPreferredAddressRequirementTestSupport.PreferredAddressTransportParameterId,
            out int preferredAddressOffset,
            out int preferredAddressLength));

        byte[] expectedPreferredAddress = QuicTransportParameterTestData.BuildPreferredAddressValue(
            QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address,
            443,
            QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address,
            8443,
            QuicPreferredAddressRequirementTestSupport.PreferredConnectionId,
            QuicPreferredAddressRequirementTestSupport.StatelessResetToken);
        Assert.True(expectedPreferredAddress.AsSpan().SequenceEqual(
            transportParameters.Slice(preferredAddressOffset, preferredAddressLength)));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(443, parsed.PreferredAddress.IPv4Port);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address, parsed.PreferredAddress.IPv6Address);
        Assert.Equal(8443, parsed.PreferredAddress.IPv6Port);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredConnectionId, parsed.PreferredAddress.ConnectionId);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.StatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }

    private static ReadOnlySpan<byte> GetOnlyTransportParametersExtension(ReadOnlySpan<byte> encryptedExtensions)
    {
        Assert.True(encryptedExtensions.Length >= 10);
        int bodyLength = ReadUInt24(encryptedExtensions.Slice(1, 3));
        Assert.Equal(encryptedExtensions.Length - 4, bodyLength);

        ushort extensionsLength = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(4, 2));
        Assert.Equal(encryptedExtensions.Length - 6, extensionsLength);

        ushort extensionType = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(6, 2));
        Assert.Equal(QuicTransportParametersCodec.QuicTransportParametersExtensionType, extensionType);

        ushort extensionLength = BinaryPrimitives.ReadUInt16BigEndian(encryptedExtensions.Slice(8, 2));
        Assert.Equal(encryptedExtensions.Length - 10, extensionLength);

        return encryptedExtensions.Slice(10, extensionLength);
    }

    private static bool TryFindTransportParameter(
        ReadOnlySpan<byte> transportParameters,
        ulong parameterId,
        out int valueOffset,
        out int valueLength)
    {
        valueOffset = 0;
        valueLength = 0;
        int index = 0;

        while (index < transportParameters.Length)
        {
            if (!QuicVariableLengthInteger.TryParse(
                    transportParameters[index..],
                    out ulong parsedParameterId,
                    out int parameterIdBytes))
            {
                return false;
            }

            index += parameterIdBytes;
            if (!QuicVariableLengthInteger.TryParse(
                    transportParameters[index..],
                    out ulong parsedLength,
                    out int parameterLengthBytes))
            {
                return false;
            }

            index += parameterLengthBytes;
            if (parsedLength > (ulong)(transportParameters.Length - index))
            {
                return false;
            }

            if (parsedParameterId == parameterId)
            {
                valueOffset = index;
                valueLength = checked((int)parsedLength);
                return true;
            }

            index += checked((int)parsedLength);
        }

        return false;
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source)
    {
        return (source[0] << 16) | (source[1] << 8) | source[2];
    }
}
