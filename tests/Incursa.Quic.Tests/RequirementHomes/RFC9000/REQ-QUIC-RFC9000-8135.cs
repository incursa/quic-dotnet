namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-8135">If address-validation token validation succeeds, the server SHOULD allow the handshake to proceed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-8135")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_8135
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-8135")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidNewToken_AllowsTheServerHandshakeToProceedWithoutRetry()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(protector);
        byte[] token = scenario.IssueNewTokenForClient();

        scenario.SendInitialWithToken(token);

        await scenario.WaitForCallbackAsync();
        Assert.True(scenario.ListenerHost.NewTokenValidationSucceeded);
        Assert.False(scenario.ListenerHost.RetryBootstrapIssued);
        Assert.True(scenario.CallbackEntered.IsCompleted);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-8135")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidRetryToken_AllowsTheServerHandshakeToProceed()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync();
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForCallbackAsync();
        await scenario.WaitForReplayAdmittedAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayAdmitted);
        Assert.True(scenario.CallbackEntered.IsCompleted);
    }

    private static QuicAddressValidationTokenProtector CreateProtector()
    {
        return new QuicAddressValidationTokenProtector(CreateSecret(), TimeSpan.FromMinutes(5));
    }

    private static byte[] CreateSecret()
    {
        byte[] secret = new byte[QuicAddressValidationTokenProtector.SecretLength];
        for (int index = 0; index < secret.Length; index++)
        {
            secret[index] = unchecked((byte)(0xA0 + index));
        }

        return secret;
    }
}
