using System.Net;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0409">When tokens are used in Retry packets, the server SHOULD include information that allows the server to verify that the source IP address and port in client packets remain constant.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0409")]
[Collection(QuicLoopbackNetworkTestCollection.Name)]
public sealed class REQ_QUIC_RFC9000_0409
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0409")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task RetryReplayFromOriginalSourceEndpoint_IsValidatedAndAdmitted()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(CreateProtector());
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplay(retryMetadata.RetryToken);

        await scenario.WaitForCallbackAsync();
        await scenario.WaitForReplayAdmittedAsync();
        Assert.True(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(0, scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
        Assert.Equal(1, scenario.CallbackCount);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0409")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RetryReplayFromDifferentSourcePort_IsRejectedBeforeAdmission()
    {
        await using QuicS8P1P3ServerTokenValidationTestSupport.RetryValidationScenario scenario =
            await QuicS8P1P3ServerTokenValidationTestSupport.StartRetryValidationScenarioAsync(CreateProtector());
        QuicRetryBootstrapMetadata retryMetadata = await scenario.IssueRetryAsync();

        scenario.SendRetryReplayFromFreshPort(retryMetadata.RetryToken);

        await scenario.WaitForNoCallbackAsync();
        Assert.False(scenario.ListenerHost.RetryBootstrapReplayValidated);
        Assert.Equal(Convert.ToHexString(retryMetadata.RetryToken), scenario.ListenerHost.RetryBootstrapReplayTokenHex);
        Assert.Equal(
            QuicS8P1P3ServerTokenValidationTestSupport.SourceEndpointMismatchFailureCode,
            scenario.ListenerHost.RetryBootstrapReplayValidationFailureCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0409")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PortBoundRetryTokenValidation_RejectsMutatedSourcePorts()
    {
        QuicAddressValidationTokenProtector protector = CreateProtector();
        DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        byte[] token = protector.IssueNewToken("203.0.113.10", 4433, issuedAt);

        Assert.Equal(
            QuicAddressValidationTokenValidationResult.Valid,
            protector.ValidateNewToken(token, "203.0.113.10", 4433, issuedAt.AddSeconds(1)));

        Random random = new(9000);
        for (int iteration = 0; iteration < 64; iteration++)
        {
            int mutatedPort;
            do
            {
                mutatedPort = random.Next(IPEndPoint.MinPort, IPEndPoint.MaxPort + 1);
            }
            while (mutatedPort == 4433);

            Assert.Equal(
                QuicAddressValidationTokenValidationResult.IntegrityFailure,
                protector.ValidateNewToken(token, "203.0.113.10", mutatedPort, issuedAt.AddSeconds(1)));
        }
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
            secret[index] = unchecked((byte)(0xC0 + index));
        }

        return secret;
    }
}
