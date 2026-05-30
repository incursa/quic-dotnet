// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicTransportTlsBridgeStateUnitTests
{
    [Fact]
    public void TryCommitLocalTransportParameters_ClonesVersionInformationSnapshot()
    {
        QuicTransportTlsBridgeState state = new();
        uint[] availableVersions =
        [
            QuicVersionNegotiation.Version2,
            QuicVersionNegotiation.Version1,
        ];

        QuicTransportParameters parameters = new()
        {
            VersionInformation = new QuicVersionInformation
            {
                ChosenVersion = QuicVersionNegotiation.Version2,
                AvailableVersions = availableVersions,
            },
        };

        Assert.True(state.TryCommitLocalTransportParameters(parameters));

        parameters.VersionInformation!.ChosenVersion = QuicVersionNegotiation.Version1;
        parameters.VersionInformation.AvailableVersions[0] = 0x11223344;

        Assert.NotNull(state.LocalTransportParameters);
        Assert.NotNull(state.LocalTransportParameters!.VersionInformation);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.ChosenVersion);
        Assert.Equal(QuicVersionNegotiation.Version2, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[0]);
        Assert.Equal(QuicVersionNegotiation.Version1, state.LocalTransportParameters!.VersionInformation!.AvailableVersions[1]);
    }

    private static QuicTlsPacketProtectionMaterial CreateOneRttProtectionMaterial()
    {
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.OneRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            new byte[16],
            new byte[12],
            new byte[16],
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial material));
        return material;
    }

    [Fact]
    public void CanSendApplicationData_ReturnsFalseWhenNoKeysOrMaterial()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.CanSendApplicationData);
    }

    [Fact]
    public void CanSendApplicationData_ReturnsTrueWhenFullyReady()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.CanSendApplicationData);
    }

    [Fact]
    public void CanSendApplicationData_ReturnsFalseWhenTerminal()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(state.IsTerminal);
        Assert.False(state.CanSendApplicationData);
    }

    [Fact]
    public void CanSendApplicationData_ReturnsFalseBeforePeerFinishedVerified()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttProtectPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.False(state.CanSendApplicationData);
    }

    [Fact]
    public void CanReceiveApplicationData_ReturnsFalseWhenNoKeysOrMaterial()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.CanReceiveApplicationData);
    }

    [Fact]
    public void CanReceiveApplicationData_ReturnsTrueWhenFullyReady()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.CanReceiveApplicationData);
    }

    [Fact]
    public void CanReceiveApplicationData_ReturnsFalseWhenTerminal()
    {
        QuicTransportTlsBridgeState state = new();
        state.SetPeerFinishedVerifiedForTests(true);
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.FatalAlert,
            AlertDescription: 0x0032)));
        Assert.True(state.IsTerminal);
        Assert.False(state.CanReceiveApplicationData);
    }

    [Fact]
    public void CanReceiveApplicationData_ReturnsFalseBeforePeerFinishedVerified()
    {
        QuicTransportTlsBridgeState state = new();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.OneRtt)));
        QuicTlsPacketProtectionMaterial material = CreateOneRttProtectionMaterial();
        Assert.False(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.OneRttOpenPacketProtectionMaterialAvailable,
            PacketProtectionMaterial: material)));
        Assert.False(state.CanReceiveApplicationData);
    }

    [Fact]
    public void CanSendApplicationData_ZeroRttMaterialDoesNotEnableSend()
    {
        QuicTransportTlsBridgeState state = new();

        // Zero-Rtt material should not satisfy the 1-RTT send guard.
        Assert.True(QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.ZeroRtt,
            QuicAeadAlgorithm.Aes128Gcm,
            new byte[16],
            new byte[12],
            new byte[16],
            new QuicAeadUsageLimits(64, 128),
            out QuicTlsPacketProtectionMaterial zeroRttMaterial));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PacketProtectionMaterialAvailable,
            PacketProtectionMaterial: zeroRttMaterial)));
        Assert.False(state.CanSendApplicationData);
        Assert.False(state.CanReceiveApplicationData);
    }
}
