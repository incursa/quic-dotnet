namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S8P1-0002">Prior to validating the client address, servers MUST NOT send more than three times as many bytes as the number of bytes they have received.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S8P1-0002")]
public sealed class REQ_QUIC_RFC9000_S8P1_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PeerHandshakeCompletion_ValidatesTheBootstrapClientPathAndRemovesTheAmplificationCap()
    {
        // Regression from the managed interop harness handshake path on 2026-04-20:
        // the server had already received the client's completed handshake/request traffic on the
        // original path, but it still behaved as if that client address was amplification-limited.
        QuicConnectionRuntime runtime = QuicS9P3TokenEmissionTestSupport.CreateServerRuntimeReadyForTokenEmission();

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(QuicS9P3TokenEmissionTestSupport.BootstrapPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.IsValidated);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);
        Assert.Equal(ulong.MaxValue, runtime.ActivePath.Value.AmplificationState.RemainingSendBudget);
        Assert.Equal(QuicS9P3TokenEmissionTestSupport.BootstrapPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void CanSend_RejectsDataBeyondThePreValidationBudget()
    {
        QuicAntiAmplificationBudget budget = new();

        Assert.True(budget.TryRegisterReceivedDatagramPayloadBytes(100, uniquelyAttributedToSingleConnection: true));
        Assert.False(budget.CanSend(301));
        Assert.False(budget.TryConsumeSendBudget(301));
    }
}
