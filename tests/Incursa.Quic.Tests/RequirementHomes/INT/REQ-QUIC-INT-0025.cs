namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0025")]
public sealed class REQ_QUIC_INT_0025
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionmigrationSourceAddressBlockerIsFormalizedAcrossSpecAndSetup()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string setupScript = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/setup.sh");
        string readme = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/README.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0019.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0019.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0019.json");

        Assert.Contains("REQ-QUIC-INT-0025", spec, StringComparison.Ordinal);
        Assert.Contains("bounded completed source-address proof", spec, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("26174181713", spec, StringComparison.Ordinal);
        Assert.Contains("preferred migration address", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("interop-connectionmigration-source-address-blocker", gapLedger, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("## Closed Gaps", gapLedger, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REQ-QUIC-INT-0025", currentStatus, StringComparison.Ordinal);
        Assert.Contains("connectionmigration hosted corroboration is now green", currentStatus, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("26174181713", currentStatus, StringComparison.Ordinal);
        Assert.Contains("preferred_lft 0", setupScript, StringComparison.Ordinal);
        Assert.Contains("preferred migration address", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("source-address blocker", architecture, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("source-address blocker", workItem, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REQ-QUIC-INT-0025", verification, StringComparison.Ordinal);
        Assert.Contains("runner-report.json` records `connectionmigration` as `succeeded`", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConnectionmigrationSourceAddressBlockerDoesNotClaimRebindSupport()
    {
        string setupScript = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/setup.sh");
        string readme = ReadRepositoryFile("src/Incursa.Quic.InteropHarness/README.md");

        Assert.DoesNotContain("preferred_lft 1", setupScript, StringComparison.Ordinal);
        Assert.DoesNotContain("preferred_lft 1", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("preferred migration address with `preferred_lft 1`", setupScript, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("`rebind-port` as supported", readme, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("`rebind-addr` as supported", readme, StringComparison.OrdinalIgnoreCase);
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
            string helperMarker = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicInteropRunner.ps1");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(helperMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the connectionmigration source-address blocker requirement home test.");
    }
}
