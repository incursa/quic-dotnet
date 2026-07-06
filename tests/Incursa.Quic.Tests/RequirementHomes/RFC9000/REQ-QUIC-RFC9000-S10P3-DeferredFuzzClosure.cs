// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S10P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetTokenGenerationProducesStableOpaqueSixteenByteTokens()
    {
        foreach ((byte cidStart, int cidLength, byte secretStart, int secretLength) in new[]
        {
            ((byte)0x10, 1, (byte)0x90, 8),
            ((byte)0x20, 4, (byte)0xA0, 16),
            ((byte)0x30, 20, (byte)0xB0, 32),
        })
        {
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId(cidStart, cidLength);
            byte[] alternateConnectionId = QuicStatelessResetRequirementTestData.CreateConnectionId((byte)(cidStart + 1), cidLength);
            byte[] secret = QuicStatelessResetRequirementTestData.CreateSecret(secretStart, secretLength);
            byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] repeatToken = new byte[QuicStatelessReset.StatelessResetTokenLength];
            byte[] alternateToken = new byte[QuicStatelessReset.StatelessResetTokenLength];

            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secret, token, out int bytesWritten));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(connectionId, secret, repeatToken, out int repeatBytesWritten));
            Assert.True(QuicStatelessReset.TryGenerateStatelessResetToken(alternateConnectionId, secret, alternateToken, out int alternateBytesWritten));

            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, bytesWritten);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, repeatBytesWritten);
            Assert.Equal(QuicStatelessReset.StatelessResetTokenLength, alternateBytesWritten);
            Assert.Equal(token, repeatToken);
            Assert.NotEqual(token, alternateToken);

            using HMACSHA256 hmac = new(secret);
            Assert.Equal(hmac.ComputeHash(connectionId)[..QuicStatelessReset.StatelessResetTokenLength], token);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0006")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0007")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0008")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0013")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetDatagramFigure10LayoutAcrossLengths()
    {
        foreach (int datagramLength in new[] { QuicStatelessReset.MinimumDatagramLength, 22, 43, 64 })
        {
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0x20 + datagramLength));

            byte[] firstDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, datagramLength);
            byte[] secondDatagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, datagramLength);

            Assert.Equal(datagramLength, firstDatagram.Length);
            Assert.Equal(datagramLength, secondDatagram.Length);
            QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(firstDatagram);
            QuicStatelessResetRequirementTestData.AssertShortHeaderLayout(secondDatagram);
            Assert.Equal(0, firstDatagram[0] & QuicPacketHeaderBits.HeaderFormBitMask);
            Assert.NotEqual(0, firstDatagram[0] & QuicPacketHeaderBits.FixedBitMask);
            Assert.True(datagramLength - QuicStatelessReset.StatelessResetTokenLength >= QuicStatelessReset.MinimumUnpredictableBytes);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(firstDatagram, token);
            QuicStatelessResetRequirementTestData.AssertTailTokenMatches(secondDatagram, token);
            Assert.NotEqual(
                firstDatagram[..^QuicStatelessReset.StatelessResetTokenLength],
                secondDatagram[..^QuicStatelessReset.StatelessResetTokenLength]);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0023")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0024")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0025")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetTokenTailAndUnpredictableFloorAcrossLengths()
    {
        foreach (int datagramLength in new[] { QuicStatelessReset.MinimumDatagramLength, QuicStatelessReset.MinimumDatagramLength + 1, 48 })
        {
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken((byte)(0x40 + datagramLength));
            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, datagramLength);

            Assert.True(QuicStatelessReset.IsPotentialStatelessReset(datagram));
            Assert.True(QuicStatelessReset.TryGetTrailingStatelessResetToken(datagram, out ReadOnlySpan<byte> trailingToken));
            Assert.True(token.AsSpan().SequenceEqual(trailingToken));
            Assert.Equal(token, datagram[^QuicStatelessReset.StatelessResetTokenLength..]);
            Assert.True(datagram[..^QuicStatelessReset.StatelessResetTokenLength].Length >= QuicStatelessReset.MinimumUnpredictableBytes);
            Assert.True(QuicStatelessReset.MatchesAnyStatelessResetToken(datagram, token));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0010")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0027")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0028")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetLengthGuidanceAndAmplificationLimitAcrossBoundaries()
    {
        foreach (int minimumConnectionIdLength in new[] { 0, 1, 4, 8, 20 })
        {
            Assert.True(QuicStatelessReset.TryGetMinimumPacketLengthForResetResistance(
                minimumConnectionIdLength,
                out int minimumPacketLength));
            Assert.Equal(minimumConnectionIdLength + 22, minimumPacketLength);
        }

        foreach (int triggeringPacketLength in new[] { QuicStatelessReset.MinimumDatagramLength + 1, 43, 100 })
        {
            Assert.True(QuicStatelessReset.TryGetRecommendedDatagramLength(triggeringPacketLength, out int datagramLength));
            Assert.Equal(Math.Max(QuicStatelessReset.MinimumDatagramLength, triggeringPacketLength - 1), datagramLength);
            Assert.True(QuicStatelessReset.CanSendStatelessReset(
                triggeringPacketLength,
                Math.Min(datagramLength, (triggeringPacketLength * 3) - 1),
                hasLoopPreventionState: true));
            Assert.False(QuicStatelessReset.CanSendStatelessReset(
                triggeringPacketLength,
                triggeringPacketLength * 3,
                hasLoopPreventionState: true));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0014")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S10P3-0018")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_StatelessResetTokenIssuanceSurfacesAreAcceptedByReceiver()
    {
        foreach (byte tokenStart in new byte[] { 0x20, 0x50, 0x80 })
        {
            byte[] token = QuicStatelessResetRequirementTestData.CreateToken(tokenStart);
            byte[] connectionId = QuicStatelessResetRequirementTestData.CreateConnectionId((byte)(tokenStart + 1), 4);
            QuicNewConnectionIdFrame frame = new(tokenStart, 0, connectionId, token);
            byte[] frameDestination = new byte[64];

            Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(frame, frameDestination, out int frameBytesWritten));
            Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(
                frameDestination.AsSpan(..frameBytesWritten),
                out QuicNewConnectionIdFrame parsedFrame,
                out int frameBytesConsumed));
            Assert.Equal(frameBytesWritten, frameBytesConsumed);
            Assert.True(parsedFrame.StatelessResetToken.SequenceEqual(token));

            QuicTransportParameters parameters = new()
            {
                StatelessResetToken = token,
            };
            byte[] parameterDestination = new byte[64];
            Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
                parameters,
                QuicTransportParameterRole.Server,
                parameterDestination,
                out int parameterBytesWritten));
            Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
                parameterDestination.AsSpan(..parameterBytesWritten),
                QuicTransportParameterRole.Client,
                out QuicTransportParameters parsedParameters));
            Assert.Equal(token, parsedParameters.StatelessResetToken);

            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
            QuicConnectionPathIdentity pathIdentity = new($"203.0.113.{tokenStart}");

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryUpdateEndpointBinding(handle, pathIdentity));
            Assert.True(endpoint.TryRegisterStatelessResetToken(handle, tokenStart, token));

            byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(token, 43);
            QuicConnectionIngressResult ingressResult = endpoint.ReceiveDatagram(datagram, pathIdentity);

            Assert.Equal(QuicConnectionIngressDisposition.EndpointHandling, ingressResult.Disposition);
            Assert.Equal(QuicConnectionEndpointHandlingKind.StatelessReset, ingressResult.HandlingKind);
            Assert.Equal(handle, ingressResult.Handle);
        }
    }
}
