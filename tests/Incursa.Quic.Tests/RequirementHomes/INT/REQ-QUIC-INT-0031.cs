namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0031")]
public sealed class REQ_QUIC_INT_0031
{
    private static readonly string[] ExpectedTargets =
    [
        "incursa-client__incursa-server",
        "curl__incursa-server",
        "aioquic-client__incursa-server",
        "quiche-client__incursa-server",
        "ngtcp2-client__incursa-server",
        "incursa-client__aioquic-server",
        "incursa-client__quiche-server",
        "incursa-client__ngtcp2-server",
    ];

    private static readonly string[] ExpectedScenarios =
    [
        "get-small",
        "get-empty",
        "get-large",
        "multiple-concurrent-get",
        "not-found",
        "many-headers",
        "split-data",
        "request-cancellation",
        "goaway",
        "connection-close-in-flight",
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ExternalHttp3HarnessDefinesRequestedTargetsAndScenarios()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0025.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0025.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0025.json");
        string compose = ReadRepositoryFile("scripts/interop/http3-external/docker-compose.yml");
        string windowsScript = ReadRepositoryFile("scripts/interop/http3-external/Run-Http3ExternalInterop.ps1");
        string posixScript = ReadRepositoryFile("scripts/interop/http3-external/run-http3-external-interop.sh");
        string parser = ReadRepositoryFile("scripts/interop/http3-external/parse-http3-results.py");
        string readme = ReadRepositoryFile("scripts/interop/http3-external/README.md");
        string report = ReadRepositoryFile("docs/http3-external-interop-report.md");
        string client = ReadRepositoryFile("samples/Incursa.Quic.Http3.Client/Program.cs");
        string server = ReadRepositoryFile("samples/Incursa.Quic.Http3.FileServer/Program.cs");

        Assert.Contains("REQ-QUIC-INT-0031", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0025", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0025", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0025", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0031", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0031", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0031", verification, StringComparison.Ordinal);

        foreach (string target in ExpectedTargets)
        {
            Assert.Contains(target, spec, StringComparison.Ordinal);
            Assert.Contains(target, windowsScript, StringComparison.Ordinal);
            Assert.Contains(target, posixScript, StringComparison.Ordinal);
            Assert.Contains(target, readme, StringComparison.Ordinal);
            Assert.Contains(target, report, StringComparison.Ordinal);
        }

        foreach (string scenario in ExpectedScenarios)
        {
            Assert.Contains(scenario, spec, StringComparison.Ordinal);
            Assert.Contains(scenario, windowsScript, StringComparison.Ordinal);
            Assert.Contains(scenario, posixScript, StringComparison.Ordinal);
            Assert.Contains(scenario, readme, StringComparison.Ordinal);
            Assert.Contains(scenario, report, StringComparison.Ordinal);
        }

        Assert.Contains("incursa-server", compose, StringComparison.Ordinal);
        Assert.Contains("incursa-client", compose, StringComparison.Ordinal);
        Assert.Contains("aioquic", compose, StringComparison.Ordinal);
        Assert.Contains("quiche", compose, StringComparison.Ordinal);
        Assert.Contains("ngtcp2", compose, StringComparison.Ordinal);
        Assert.Contains("results.jsonl", windowsScript, StringComparison.Ordinal);
        Assert.Contains("report.md", windowsScript, StringComparison.Ordinal);
        Assert.Contains("parse-http3-results.py", windowsScript, StringComparison.Ordinal);
        Assert.Contains("results.jsonl", posixScript, StringComparison.Ordinal);
        Assert.Contains("report.md", posixScript, StringComparison.Ordinal);
        Assert.Contains("parse-http3-results.py", posixScript, StringComparison.Ordinal);
        Assert.Contains("External HTTP/3 Interop Report", parser, StringComparison.Ordinal);
        Assert.Contains("--expect-status", client, StringComparison.Ordinal);
        Assert.Contains("IPAddress.Any", server, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ExternalHttp3HarnessKeepsSkippedRowsExplicit()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0025.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0025.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0025.json");
        string windowsScript = ReadRepositoryFile("scripts/interop/http3-external/Run-Http3ExternalInterop.ps1");
        string posixScript = ReadRepositoryFile("scripts/interop/http3-external/run-http3-external-interop.sh");
        string parser = ReadRepositoryFile("scripts/interop/http3-external/parse-http3-results.py");
        string readme = ReadRepositoryFile("scripts/interop/http3-external/README.md");

        Assert.Contains("skipped or failed rows explicit", spec, StringComparison.Ordinal);
        Assert.Contains("not support evidence", architecture, StringComparison.Ordinal);
        Assert.Contains("does not promote broad HTTP/3 peer support", workItem, StringComparison.Ordinal);
        Assert.Contains("must not be converted into support claims", verification, StringComparison.Ordinal);
        Assert.Contains("first-class result", verification, StringComparison.Ordinal);
        Assert.Contains("scenario requires a specialized peer behavior that is not wired", windowsScript, StringComparison.Ordinal);
        Assert.Contains("target is listed for matrix coverage but requires an external peer command image/server wiring", windowsScript, StringComparison.Ordinal);
        Assert.Contains("scenario requires a specialized peer behavior that is not wired", posixScript, StringComparison.Ordinal);
        Assert.Contains("target is listed for matrix coverage but requires an external peer command image/server wiring", posixScript, StringComparison.Ordinal);
        Assert.Contains("\"skip\": \"SKIP\"", parser, StringComparison.Ordinal);
        Assert.Contains("reported as `skip`", readme, StringComparison.Ordinal);
        Assert.Contains("must not be used to claim broad RFC 9114/RFC 9204 completeness", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("complete RFC 9114 support", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("complete RFC 9204 support", spec, StringComparison.OrdinalIgnoreCase);
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
            string harnessMarker = Path.Combine(current.FullName, "scripts", "interop", "http3-external", "docker-compose.yml");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(harnessMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the external HTTP/3 interop requirement home test.");
    }
}
