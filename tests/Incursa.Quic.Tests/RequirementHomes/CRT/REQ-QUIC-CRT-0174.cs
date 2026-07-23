// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0174")]
public sealed class REQ_QUIC_CRT_0174
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstructionProvenanceUsesItsOwnCanonicalAxisAndPolicyContract()
    {
        using JsonDocument row = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/construction-row.send-turn.forced.example.json");

        JsonElement root = row.RootElement;
        Assert.Equal("adaptive-runtime-policy-construction-dataset-v1", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("application_send_turn_planning", root.GetProperty("axisId").GetString());
        JsonElement state = root.GetProperty("constructionPolicyState");
        Assert.Equal("adaptive-runtime-application-send-turn-provenance-v1", state.GetProperty("provenanceContractVersion").GetString());
        Assert.Equal("application-send-turn-force-v1", state.GetProperty("ruleVersion").GetString());
        Assert.Equal("forced", state.GetProperty("selectionSource").GetString());
        Assert.True(root.GetProperty("workloadAnalysisOnly").GetProperty("excludedFromProductionFeatures").GetBoolean());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructionSchemaDoesNotPermitReceiveCreditEpochFields()
    {
        using JsonDocument schema = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryJson(
            "schemas/adaptive-runtime-policy-construction-dataset-v1.schema.json");

        JsonElement properties = schema.RootElement.GetProperty("properties");
        Assert.False(properties.TryGetProperty("preDecisionObservations", out _));
        Assert.False(properties.TryGetProperty("currentPolicyState", out _));
        Assert.False(properties.TryGetProperty("transitionState", out _));
        Assert.False(properties.TryGetProperty("epochIndex", out _));
        Assert.True(properties.GetProperty("axisId").GetProperty("const").GetString() == "application_send_turn_planning");
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstructionProvenanceExporterNormalizesTheRuntimeEnumAndRetainsChecksums()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"send-turn-construction-export-{Guid.NewGuid():N}");
        string outputDirectory = Path.Combine(temporaryDirectory, "export");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1",
                    "-RawProvenancePath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                        "tests/fixtures/adaptive-runtime-policy/application-send-turn-provenance.raw.example.jsonl"),
                    "-OutputDirectory", outputDirectory,
                    "-DatasetId", "send-turn-test-dataset",
                    "-CampaignId", "send-turn-test-campaign",
                    "-RunId", "send-turn-test-run",
                    "-CellId", "send-turn-test-cell",
                    "-SampleId", "send-turn-test-sample",
                    "-ExpectedPolicy", "legacy_current",
                    "-BenchmarkSha256", new string('a', 64),
                    "-RuntimeSha256", new string('b', 64),
                    "-HostFingerprint", "test-host-fingerprint",
                    "-ScenarioId", "quic.transport.stream-throughput.1mb",
                    "-Connections", "1",
                    "-StreamsPerConnection", "1",
                    "-WarmupMicros", "0",
                    "-MeasurementMicros", "1000",
                    "-RepositoryRoot", repoRoot,
                    "-RepositoryCommit", "0123456789abcdef0123456789abcdef01234567");

            Assert.Equal(0, result.ExitCode);
            string rowPath = Assert.Single(Directory.GetFiles(outputDirectory, "construction-row-*.json"));
            using JsonDocument row = JsonDocument.Parse(File.ReadAllText(rowPath));
            JsonElement root = row.RootElement;
            Assert.Equal("legacy_current", root.GetProperty("constructionPolicyState").GetProperty("appliedPolicy").GetString());
            Assert.Equal("forced", root.GetProperty("constructionPolicyState").GetProperty("selectionSource").GetString());
            Assert.Equal(
                Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(
                    AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                        "tests/fixtures/adaptive-runtime-policy/application-send-turn-provenance.raw.example.jsonl")))).ToLowerInvariant(),
                root.GetProperty("provenance").GetProperty("sourceArtifactSha256").GetString());

            using JsonDocument manifest = JsonDocument.Parse(File.ReadAllText(
                Path.Combine(outputDirectory, "construction-provenance-export-manifest.json")));
            Assert.Equal(1, manifest.RootElement.GetProperty("rowCount").GetInt32());
            Assert.Equal(1, manifest.RootElement.GetProperty("rowChecksums").GetArrayLength());
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ConstructionProvenanceExporterRejectsTreatmentMismatchWithoutOverwritingOutput()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"send-turn-construction-mismatch-{Guid.NewGuid():N}");
        string outputDirectory = Path.Combine(temporaryDirectory, "export");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1",
                    "-RawProvenancePath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                        "tests/fixtures/adaptive-runtime-policy/application-send-turn-provenance.raw.example.jsonl"),
                    "-OutputDirectory", outputDirectory,
                    "-DatasetId", "send-turn-test-dataset",
                    "-CampaignId", "send-turn-test-campaign",
                    "-RunId", "send-turn-test-run",
                    "-CellId", "send-turn-test-cell",
                    "-SampleId", "send-turn-test-sample",
                    "-ExpectedPolicy", "conservative",
                    "-BenchmarkSha256", new string('a', 64),
                    "-RuntimeSha256", new string('b', 64),
                    "-HostFingerprint", "test-host-fingerprint",
                    "-ScenarioId", "quic.transport.stream-throughput.1mb",
                    "-Connections", "1",
                    "-StreamsPerConnection", "1",
                    "-WarmupMicros", "0",
                    "-MeasurementMicros", "1000",
                    "-RepositoryRoot", repoRoot,
                    "-RepositoryCommit", "0123456789abcdef0123456789abcdef01234567");

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("policy mismatch", result.Output, StringComparison.Ordinal);
            Assert.Empty(Directory.GetFiles(outputDirectory, "construction-row-*.json"));
        }
        finally
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
    }
}
