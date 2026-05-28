// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0014">The value in the Unused field is set to an arbitrary value by the server; a client MUST ignore these bits.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P5-0014")]
public sealed class REQ_QUIC_RFC9000_S17P2P5_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P5-0014">The value in the Unused field is set to an arbitrary value by the server; a client MUST ignore these bits.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S17P2P5-0014")]
    public void RetryMetadataParserIgnoresUnusedBitsInTheRetryHeader()
    {
        byte[] originalDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x20, 0x21, 0x22, 0x23,
        ];
        byte[] retrySourceConnectionId =
        [
            0x31, 0x32, 0x33,
        ];
        byte[] retryToken =
        [
            0x41, 0x42, 0x43, 0x44,
        ];

        byte[] retryPacket = QuicRetryPacketRequirementTestData.BuildRetryPacket(
            destinationConnectionId: retryPacketDestinationConnectionId,
            sourceConnectionId: retrySourceConnectionId,
            retryToken: retryToken,
            unusedBits: 0x0A);

        Assert.True(QuicRetryIntegrity.TryGenerateRetryIntegrityTag(
            originalDestinationConnectionId,
            retryPacket.AsSpan(0, retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            retryPacket.AsSpan(retryPacket.Length - QuicRetryIntegrity.RetryIntegrityTagLength),
            out int integrityTagBytesWritten));
        Assert.Equal(QuicRetryIntegrity.RetryIntegrityTagLength, integrityTagBytesWritten);

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, retryPacket));
        Assert.True(QuicPacketParser.TryParseLongHeader(retryPacket, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x0A, header.TypeSpecificBits);
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata retryMetadata));
        Assert.Equal(retryToken, retryMetadata.RetryToken);
    }
}
