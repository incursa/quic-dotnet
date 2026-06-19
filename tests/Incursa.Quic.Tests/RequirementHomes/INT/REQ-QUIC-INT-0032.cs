// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
[Requirement("REQ-QUIC-INT-0032")]
public sealed class REQ_QUIC_INT_0032
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void H3SpecPipelineIsTraceLinkedAcrossCanonicalArtifacts()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0026.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0026.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0026.json");
        string startScript = ReadRepositoryFile("scripts/interop/http3-h3spec/Start-H3SpecServer.ps1");
        string installScript = ReadRepositoryFile("scripts/interop/http3-h3spec/Install-H3SpecTool.ps1");
        string runScript = ReadRepositoryFile("scripts/interop/http3-h3spec/Run-H3Spec.ps1");
        string stopScript = ReadRepositoryFile("scripts/interop/http3-h3spec/Stop-H3SpecServer.ps1");
        string parser = ReadRepositoryFile("scripts/interop/http3-h3spec/parse-h3spec-results.py");
        string readme = ReadRepositoryFile("scripts/interop/http3-h3spec/README.md");
        string workflow = ReadRepositoryFile(".github/workflows/http3-h3spec.yml");
        string reportTemplate = ReadRepositoryFile("docs/h3spec-failure-triage-report.md");

        Assert.Contains("REQ-QUIC-INT-0032", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-INT-0026", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-INT-0026", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0026", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0032", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0032", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0032", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0032", gapLedger, StringComparison.Ordinal);
        Assert.Contains("Start-H3SpecServer.ps1", spec, StringComparison.Ordinal);
        Assert.Contains("Run-H3Spec.ps1", spec, StringComparison.Ordinal);
        Assert.Contains("parse-h3spec-results.py", spec, StringComparison.Ordinal);
        Assert.Contains("h3spec HTTP/3 server conformance pipeline", spec, StringComparison.Ordinal);

        Assert.Contains("Incursa.Quic.Http3.FileServer.csproj", startScript, StringComparison.Ordinal);
        Assert.Contains("openssl", startScript, StringComparison.Ordinal);
        Assert.Contains("server-context.json", startScript, StringComparison.Ordinal);
        Assert.Contains("v0.1.13", installScript, StringComparison.Ordinal);
        Assert.Contains("host.docker.internal", installScript, StringComparison.Ordinal);
        Assert.Contains("Invoke-H3SpecDocker.ps1", installScript, StringComparison.Ordinal);
        Assert.Contains("AcquireH3Spec", runScript, StringComparison.Ordinal);
        Assert.Contains("RedirectStandardOutput", runScript, StringComparison.Ordinal);
        Assert.Contains("RedirectStandardError", runScript, StringComparison.Ordinal);
        Assert.Contains("h3spec-results.json", runScript, StringComparison.Ordinal);
        Assert.Contains("h3spec-report.md", runScript, StringComparison.Ordinal);
        Assert.Contains("Stop-Process", stopScript, StringComparison.Ordinal);
        Assert.Contains("RFC 9114", parser, StringComparison.Ordinal);
        Assert.Contains("RFC 9204", parser, StringComparison.Ordinal);
        Assert.Contains("http3-adapter-boundary", parser, StringComparison.Ordinal);
        Assert.Contains("qpack-stream-state-boundary", parser, StringComparison.Ordinal);
        Assert.Contains("h3spec-0.1.13", workflow, StringComparison.Ordinal);
        Assert.Contains("workflow_dispatch", workflow, StringComparison.Ordinal);
        Assert.Contains("plan-only", workflow, StringComparison.Ordinal);
        Assert.Contains("Run-H3Spec.ps1", workflow, StringComparison.Ordinal);
        Assert.Contains("h3spec [options] <host> <port>", readme, StringComparison.Ordinal);
        Assert.Contains("Follow-Up Rules", reportTemplate, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void H3SpecPipelineKeepsConformanceFailuresAdvisoryUntilProtocolOwned()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0026.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0026.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0026.json");
        string readme = ReadRepositoryFile("scripts/interop/http3-h3spec/README.md");
        string reportTemplate = ReadRepositoryFile("docs/h3spec-failure-triage-report.md");

        Assert.Contains("advisory", spec, StringComparison.Ordinal);
        Assert.Contains("opt-in or non-gating", spec, StringComparison.Ordinal);
        Assert.Contains("complete RFC 9114 or RFC 9204 support", architecture, StringComparison.Ordinal);
        Assert.Contains("fixing protocol failures discovered by h3spec", workItem, StringComparison.Ordinal);
        Assert.Contains("Plan-only CI evidence proves the harness shape", architecture, StringComparison.Ordinal);
        Assert.Contains("protocol-owned requirements", verification, StringComparison.Ordinal);
        Assert.Contains("does not promote HTTP/3 or QPACK support by itself", readme, StringComparison.Ordinal);
        Assert.Contains("A green h3spec run is evidence for the h3spec harness only", reportTemplate, StringComparison.Ordinal);
        Assert.DoesNotContain("complete RFC 9114 support", spec, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("complete RFC 9204 support", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void H3SpecParserMapsHttp3AndQpackFailuresToTriageTodos()
    {
        string parser = ReadRepositoryFile("scripts/interop/http3-h3spec/parse-h3spec-results.py");

        Assert.Contains("\"HTTP/3\": \"RFC 9114\"", parser, StringComparison.Ordinal);
        Assert.Contains("\"QPACK\": \"RFC 9204\"", parser, StringComparison.Ordinal);
        Assert.Contains("\"RFC 9114\": \"http3-adapter-boundary\"", parser, StringComparison.Ordinal);
        Assert.Contains("\"RFC 9204\": \"qpack-stream-state-boundary\"", parser, StringComparison.Ordinal);
        Assert.Contains("TODO: {todo}", parser, StringComparison.Ordinal);
        Assert.Contains("normalize_case_name", parser, StringComparison.Ordinal);
        Assert.Contains("failureDetail", parser, StringComparison.Ordinal);
        Assert.Contains("RFC 9114/RFC 9204 failures", parser, StringComparison.Ordinal);
        Assert.Contains("Create or update a protocol-owned requirement/test", parser, StringComparison.Ordinal);
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
            string harnessMarker = Path.Combine(current.FullName, "scripts", "interop", "http3-h3spec", "Run-H3Spec.ps1");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(harnessMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the h3spec requirement home test.");
    }
}
