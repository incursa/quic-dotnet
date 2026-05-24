namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0026")]
public sealed class REQ_QUIC_INT_0026
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void SimulatorScenarioAccountingIsTraceLinkedAcrossCanonicalArtifacts()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string plan = ReadRepositoryFile("docs/network-simulator-correctness-plan.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0020.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0020.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0020.json");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1");

        Assert.Contains("REQ-QUIC-INT-0026", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0020", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0020", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0020", spec, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-BASE-0001", plan, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-LOSS-0001", plan, StringComparison.Ordinal);
        Assert.Contains("correctness", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("advisory-interop", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("performance-only", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sim/scenarios/simple-p2p/README.md", plan, StringComparison.Ordinal);
        Assert.Contains("sim/scenarios/droplist/README.md", plan, StringComparison.Ordinal);
        Assert.DoesNotContain("interop-network-simulator-backed-test-surface", gapLedger, StringComparison.Ordinal);
        Assert.Contains("scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1", architecture, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-BASE-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-LOSS-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("NetworkSimulatorScenarioScriptTests", verification, StringComparison.Ordinal);
        Assert.Contains("accepts those preserved baseline and deterministic-loss execution bundles", verification, StringComparison.Ordinal);
        Assert.Contains("closes the `interop-network-simulator-backed-test-surface` gap", verification, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-BASE-0001", helper, StringComparison.Ordinal);
        Assert.Contains("SIM-QUIC-LOSS-0001", helper, StringComparison.Ordinal);
        Assert.Contains("Copy-SimulatorLogs", helper, StringComparison.Ordinal);
        Assert.Contains("SimulatorLogs:", helper, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SimulatorScenarioAccountingDoesNotPromoteAdvisoryOrPerformanceRows()
    {
        string plan = ReadRepositoryFile("docs/network-simulator-correctness-plan.md");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0020.json");
        string helper = ReadRepositoryFile("scripts/interop/Invoke-QuicNetworkSimulatorScenario.ps1");

        Assert.Contains("no protocol correctness claim is promoted", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("performance-only", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("advisory", plan, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not-promoted", helper, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Requirement promotion still requires linked runtime evidence", helper, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SIM-QUIC-REBIND-0001\"", helper, StringComparison.Ordinal);
        Assert.DoesNotContain("SIM-QUIC-XTRAFFIC-0001\"", helper, StringComparison.Ordinal);
        Assert.Contains("Advisory interop and performance-only scenarios must remain non-promoting", verification, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-INT.json");
            string helperMarker = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicNetworkSimulatorScenario.ps1");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(helperMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the simulator scenario accounting requirement home test.");
    }
}
