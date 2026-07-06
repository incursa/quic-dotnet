// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9001-S6-P3-S2-R02">An endpoint that notices a changed Key Phase bit MUST decrypt the packet that contains the changed value.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9001-S6-P3-S2-R02")]
public sealed class RFC9001_S6_P3_S2_R02
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenProtectedApplicationDataPacket_DecryptsTheFirstObservedPhaseOnePacketWithSuccessorMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.True(QuicPacketParser.TryParseShortHeader(openedPacket, out QuicShortHeaderPacket parsedHeader));
        Assert.True(parsedHeader.KeyPhase);
        Assert.NotEmpty(openedPacket);
        Assert.True(payloadOffset > 0);
        Assert.True(payloadLength > 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenProtectedApplicationDataPacket_DoesNotDecryptATamperedSuccessorPacket()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.CreateTamperedSuccessorPhaseOneApplicationPacket(successorOpenMaterial);

        QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

        Assert.False(coordinator.TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CapturedTransferPhaseOnePacketDecryptsWithSuccessorAeadMaterialAndTheRetainedCurrentHeaderProtectionKey()
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateTransferPhaseOneServerOpenMaterialWithRetainedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial successorOpenMaterial));

        Assert.True(QuicCapturedInteropTransferEvidence.TryOpenTransferPhaseOneServerPacket(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected,
            successorOpenMaterial,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool observedKeyPhase));

        Assert.True(observedKeyPhase);
        Assert.Equal(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Payload,
            openedPacket.AsSpan(payloadOffset, payloadLength).ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CapturedTransferPhaseOnePacketDoesNotDecryptWhenTheHeaderProtectionKeyAlsoRotates()
    {
        Assert.True(QuicCapturedInteropTransferEvidence.TryCreateTransferPhaseOneServerOpenMaterialWithDerivedHeaderProtectionKey(
            out QuicTlsPacketProtectionMaterial successorOpenMaterial));

        Assert.False(QuicCapturedInteropTransferEvidence.TryOpenTransferPhaseOneServerPacket(
            QuicCapturedInteropTransferEvidence.QuicGoTransferKeyUpdatePacket101Protected,
            successorOpenMaterial,
            out _,
            out _,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryOpenProtectedApplicationDataPacket_DecryptsChangedKeyPhasePacketsWithSuccessorMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial successorOpenMaterial,
            out _));

        foreach (byte[] payload in new[]
        {
            QuicRfc9001KeyPhaseTestSupport.CreatePingPayload(),
            new byte[] { 0x00, 0x01 },
            new byte[] { 0x00, 0x00, 0x01 },
            new byte[] { 0x01, 0x00, 0x00, 0x00 },
        })
        {
            byte[] protectedPacket = QuicRfc9001KeyPhaseTestSupport.BuildProtectedApplicationPacket(
                successorOpenMaterial,
                keyPhase: true,
                payload);

            QuicHandshakeFlowCoordinator coordinator = QuicRfc9001KeyPhaseTestSupport.CreatePacketCoordinator();

            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                protectedPacket,
                successorOpenMaterial,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength,
                out bool observedKeyPhase));

            Assert.True(observedKeyPhase);
            ReadOnlySpan<byte> openedPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
            Assert.True(openedPayload.Length >= payload.Length);
            Assert.Equal(payload, openedPayload[..payload.Length].ToArray());
            Assert.All(openedPayload[payload.Length..].ToArray(), static value => Assert.Equal(0, value));
        }
    }
}
