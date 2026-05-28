// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S12P1-0002">Retry packets use an AEAD function [AEAD] to protect against accidental modification.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S12P1-0002")]
public sealed class REQ_QUIC_RFC9000_S12P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildRetryPacket_ProducesAnIntegrityProtectedPacket()
    {
        byte[] originalDestinationConnectionId =
        [
            0x11, 0x12, 0x13, 0x14,
        ];
        byte[] retryPacketDestinationConnectionId =
        [
            0x21, 0x22, 0x23, 0x24,
        ];
        byte[] retrySourceConnectionId =
        [
            0x31, 0x32, 0x33,
        ];
        byte[] retryToken =
        [
            0x41, 0x42, 0x43, 0x44,
        ];

        Assert.True(QuicRetryIntegrity.TryBuildRetryPacket(
            originalDestinationConnectionId,
            retryPacketDestinationConnectionId,
            retrySourceConnectionId,
            retryToken,
            out byte[] retryPacket));

        Assert.True(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, retryPacket));
        Assert.True(QuicRetryIntegrity.TryParseRetryBootstrapMetadata(
            originalDestinationConnectionId,
            retryPacket,
            out QuicRetryBootstrapMetadata metadata));
        Assert.True(retrySourceConnectionId.AsSpan().SequenceEqual(metadata.RetrySourceConnectionId));
        Assert.True(retryToken.AsSpan().SequenceEqual(metadata.RetryToken));

        byte[] tamperedRetryPacket = retryPacket.ToArray();
        tamperedRetryPacket[^1] ^= 0x01;

        Assert.False(QuicRetryIntegrity.TryValidateRetryPacketIntegrity(originalDestinationConnectionId, tamperedRetryPacket));
    }
}
