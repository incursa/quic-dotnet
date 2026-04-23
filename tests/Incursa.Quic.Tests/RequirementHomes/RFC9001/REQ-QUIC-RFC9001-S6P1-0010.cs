namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0010">An endpoint MUST derive the updated packet protection key and IV from the updated secret as defined for QUIC packet protection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0010")]
public sealed class REQ_QUIC_RFC9001_S6P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleSuccessorPacketKeysAndIvsMatchIndependentDerivationFromUpdatedSecrets()
    {
        AssertSuccessorPacketKeysAndIvsMatchIndependentDerivationFromUpdatedSecrets(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime,
            useClientTrafficSecretForWriteSecret: true);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleSuccessorPacketKeysAndIvsMatchIndependentDerivationFromUpdatedSecrets()
    {
        AssertSuccessorPacketKeysAndIvsMatchIndependentDerivationFromUpdatedSecrets(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(),
            useClientTrafficSecretForWriteSecret: false);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CurrentTrafficSecretsDoNotMatchTheRuntimeSuccessorPacketKeysOrIvs()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeApplicationTrafficSecrets(
            runtime,
            out byte[] clientApplicationTrafficSecret,
            out byte[] serverApplicationTrafficSecret));

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorProtectMaterial));

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            serverApplicationTrafficSecret,
            currentOpenMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial currentSecretOpenMaterial));
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            clientApplicationTrafficSecret,
            currentProtectMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial currentSecretProtectMaterial));

        Assert.False(currentSecretOpenMaterial.Matches(runtimeSuccessorOpenMaterial));
        Assert.False(currentSecretProtectMaterial.Matches(runtimeSuccessorProtectMaterial));
    }

    private static void AssertSuccessorPacketKeysAndIvsMatchIndependentDerivationFromUpdatedSecrets(
        Func<QuicConnectionRuntime> runtimeFactory,
        bool useClientTrafficSecretForWriteSecret)
    {
        using QuicConnectionRuntime runtime = runtimeFactory();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeApplicationTrafficSecrets(
            runtime,
            out byte[] clientApplicationTrafficSecret,
            out byte[] serverApplicationTrafficSecret));

        ReadOnlySpan<byte> currentWriteTrafficSecret = useClientTrafficSecretForWriteSecret
            ? clientApplicationTrafficSecret
            : serverApplicationTrafficSecret;
        ReadOnlySpan<byte> currentReadTrafficSecret = useClientTrafficSecretForWriteSecret
            ? serverApplicationTrafficSecret
            : clientApplicationTrafficSecret;

        QuicTlsPacketProtectionMaterial currentOpenMaterial =
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorOpenMaterial,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorProtectMaterial));

        byte[] expectedNextReadSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveQuicKeyUpdateTrafficSecret(currentReadTrafficSecret);
        byte[] expectedNextWriteSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveQuicKeyUpdateTrafficSecret(currentWriteTrafficSecret);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            expectedNextReadSecret,
            currentOpenMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial expectedSuccessorOpenMaterial));
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            expectedNextWriteSecret,
            currentProtectMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial expectedSuccessorProtectMaterial));

        Assert.True(expectedSuccessorOpenMaterial.AeadKey.SequenceEqual(runtimeSuccessorOpenMaterial.AeadKey));
        Assert.True(expectedSuccessorOpenMaterial.AeadIv.SequenceEqual(runtimeSuccessorOpenMaterial.AeadIv));
        Assert.True(expectedSuccessorProtectMaterial.AeadKey.SequenceEqual(runtimeSuccessorProtectMaterial.AeadKey));
        Assert.True(expectedSuccessorProtectMaterial.AeadIv.SequenceEqual(runtimeSuccessorProtectMaterial.AeadIv));
        Assert.True(expectedSuccessorOpenMaterial.Matches(runtimeSuccessorOpenMaterial));
        Assert.True(expectedSuccessorProtectMaterial.Matches(runtimeSuccessorProtectMaterial));
    }
}
