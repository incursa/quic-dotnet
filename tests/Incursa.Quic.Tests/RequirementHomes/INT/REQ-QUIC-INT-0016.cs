namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0016")]
public sealed class REQ_QUIC_INT_0016
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ManualHostedHandshakeWorkflowUsesSeparateCheckoutsAndTheNarrowHelperCell()
    {
        string workflow = ReadWorkflow();

        Assert.Contains("workflow_dispatch:", workflow, StringComparison.Ordinal);
        Assert.Contains("default: hosted-handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("Checkout quic-dotnet", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-dotnet", workflow, StringComparison.Ordinal);
        Assert.Contains("Checkout quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("repository: quic-interop/quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-interop-runner", workflow, StringComparison.Ordinal);
        Assert.Contains("-LocalRole server", workflow, StringComparison.Ordinal);
        Assert.Contains("-PeerImplementationSlots quic-go", workflow, StringComparison.Ordinal);
        Assert.Contains("-TestCases handshake", workflow, StringComparison.Ordinal);
        Assert.Contains("if: always()", workflow, StringComparison.Ordinal);
        Assert.Contains("path: quic-dotnet/artifacts/interop-runner/server-handshake-quic-go/", workflow, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ManualHostedHandshakeWorkflowDoesNotJoinOrdinaryCiTriggers()
    {
        string workflow = ReadWorkflow();

        Assert.DoesNotContain("\npush:", workflow, StringComparison.Ordinal);
        Assert.DoesNotContain("\npull_request:", workflow, StringComparison.Ordinal);
    }

    private static string ReadWorkflow()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, ".github", "workflows", "interop-runner-handshake.yml");
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate .github/workflows/interop-runner-handshake.yml.");
    }
}
