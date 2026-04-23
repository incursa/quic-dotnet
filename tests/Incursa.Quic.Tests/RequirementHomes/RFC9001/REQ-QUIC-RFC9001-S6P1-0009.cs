using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9001-S6P1-0009">An endpoint MUST derive the next write secret from the current write secret using the TLS-provided KDF and the label "quic ku".</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9001-S6P1-0009")]
public sealed class REQ_QUIC_RFC9001_S6P1_0009
{
    private static readonly byte[] WrongKeyUpdateLabel = Encoding.ASCII.GetBytes("quic wrong");

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRoleSuccessorWriteMaterialMatchesTheQuicKeyUpdateLabel()
    {
        AssertRuntimeSuccessorWriteMaterialMatchesTheQuicKeyUpdateLabel(
            QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime,
            useClientTrafficSecretForWriteSecret: true);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerRoleSuccessorWriteMaterialMatchesTheQuicKeyUpdateLabel()
    {
        AssertRuntimeSuccessorWriteMaterialMatchesTheQuicKeyUpdateLabel(
            () => QuicPostHandshakeTicketTestSupport.CreateFinishedServerRuntime(),
            useClientTrafficSecretForWriteSecret: false);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void WrongKeyUpdateLabelDoesNotMatchTheRuntimeSuccessorWriteMaterial()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeApplicationTrafficSecrets(
            runtime,
            out byte[] clientApplicationTrafficSecret,
            out _));

        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out _,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorProtectMaterial));

        byte[] wrongNextWriteSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveTrafficSecretWithLabel(clientApplicationTrafficSecret, WrongKeyUpdateLabel);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            wrongNextWriteSecret,
            currentProtectMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial wrongSuccessorProtectMaterial));

        Assert.False(wrongSuccessorProtectMaterial.Matches(runtimeSuccessorProtectMaterial));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeAdvancesStoredTrafficSecretsAfterFirstKeyUpdate()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        QuicRfc9001KeyPhaseTestSupport.ConfigureKeyPhaseDestinationConnectionId(runtime);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeApplicationTrafficSecrets(
            runtime,
            out byte[] initialClientApplicationTrafficSecret,
            out byte[] initialServerApplicationTrafficSecret));

        byte[] expectedUpdatedClientApplicationTrafficSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveQuicKeyUpdateTrafficSecret(initialClientApplicationTrafficSecret);
        byte[] expectedUpdatedServerApplicationTrafficSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveQuicKeyUpdateTrafficSecret(initialServerApplicationTrafficSecret);

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryInstallRuntimeOneRttKeyUpdate(runtime));
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeApplicationTrafficSecrets(
            runtime,
            out byte[] advancedClientApplicationTrafficSecret,
            out byte[] advancedServerApplicationTrafficSecret));

        Assert.True(expectedUpdatedClientApplicationTrafficSecret.SequenceEqual(advancedClientApplicationTrafficSecret));
        Assert.True(expectedUpdatedServerApplicationTrafficSecret.SequenceEqual(advancedServerApplicationTrafficSecret));
        Assert.False(initialClientApplicationTrafficSecret.SequenceEqual(advancedClientApplicationTrafficSecret));
        Assert.False(initialServerApplicationTrafficSecret.SequenceEqual(advancedServerApplicationTrafficSecret));
    }

    private static void AssertRuntimeSuccessorWriteMaterialMatchesTheQuicKeyUpdateLabel(
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
        QuicTlsPacketProtectionMaterial currentProtectMaterial =
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value;

        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryGetRuntimeSuccessorPhaseOnePacketProtectionMaterial(
            runtime,
            out _,
            out QuicTlsPacketProtectionMaterial runtimeSuccessorProtectMaterial));

        byte[] expectedNextWriteSecret =
            QuicRfc9001KeyPhaseTestSupport.DeriveQuicKeyUpdateTrafficSecret(currentWriteTrafficSecret);
        Assert.True(QuicRfc9001KeyPhaseTestSupport.TryCreateOneRttPacketProtectionMaterialFromTrafficSecret(
            expectedNextWriteSecret,
            currentProtectMaterial.HeaderProtectionKey,
            out QuicTlsPacketProtectionMaterial expectedSuccessorProtectMaterial));

        Assert.True(expectedSuccessorProtectMaterial.Matches(runtimeSuccessorProtectMaterial));
    }
}
