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
            string exporterScriptPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1");
            string rawProvenancePath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/application-send-turn-provenance.raw.example.jsonl");
            string command = $$"""
                $parameters = [ordered]@{
                    RawProvenancePath = {{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(rawProvenancePath)}}
                    OutputDirectory = {{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(outputDirectory)}}
                    DatasetId = 'send-turn-test-dataset'
                    CampaignId = 'send-turn-test-campaign'
                    RunId = 'send-turn-test-run'
                    CellId = 'send-turn-test-cell'
                    SampleId = 'send-turn-test-sample'
                    ExpectedPolicy = 'legacy_current'
                    BenchmarkSha256 = '{{new string('a', 64)}}'
                    RuntimeSha256 = '{{new string('b', 64)}}'
                    HostFingerprint = 'test-host-fingerprint'
                    CorrectnessFlagsJson = '{"payloadValid":true,"protocolValid":true,"timedOut":false,"ownershipValid":true,"terminalValid":true,"violationCodes":[]}'
                    AdditionalAnalysisExclusionFlags = @('target_health_invalid', 'generator_health_invalid')
                    ScenarioId = 'quic.transport.stream-throughput.1mb'
                    Connections = 1
                    StreamsPerConnection = 1
                    WarmupMicros = 0
                    MeasurementMicros = 1000
                    RepositoryRoot = {{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(repoRoot)}}
                    RepositoryCommit = '0123456789abcdef0123456789abcdef01234567'
                }
                & {{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(exporterScriptPath)}} @parameters
                """;
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellCommand(command);

            Assert.Equal(0, result.ExitCode);
            string rowPath = Assert.Single(Directory.GetFiles(outputDirectory, "construction-row-*.json"));
            using JsonDocument row = JsonDocument.Parse(File.ReadAllText(rowPath));
            JsonElement root = row.RootElement;
            Assert.Equal("legacy_current", root.GetProperty("constructionPolicyState").GetProperty("appliedPolicy").GetString());
            Assert.Equal("forced", root.GetProperty("constructionPolicyState").GetProperty("selectionSource").GetString());
            Assert.Equal(
                ["generator_health_invalid", "target_health_invalid"],
                root.GetProperty("analysisExclusionFlags").EnumerateArray().Select(static value => value.GetString()!).ToArray());
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
                    "-CorrectnessFlagsJson", "{\"payloadValid\":true,\"protocolValid\":true,\"timedOut\":false,\"ownershipValid\":true,\"terminalValid\":true,\"violationCodes\":[]}",
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

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EvidenceValidatorJoinsConstructionRowsToForcedSendTurnEvidence()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string sourceDirectory = Path.GetDirectoryName(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json"))!;
        string temporaryDirectory = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"send-turn-construction-join-{Guid.NewGuid():N}");

        try
        {
            CopyDirectory(sourceDirectory, temporaryDirectory);
            string rawPath = Path.Combine(temporaryDirectory, "fixture-artifacts", "application-send-turn-policy.raw.jsonl");
            File.Copy(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/application-send-turn-provenance.raw.example.jsonl"),
                rawPath);

            string inventoryPath = Path.Combine(temporaryDirectory, "checksum-inventory.shadow.example.json");
            System.Text.Json.Nodes.JsonObject inventory =
                System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(inventoryPath))!.AsObject();
            inventory["files"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject
            {
                ["path"] = "fixture-artifacts/application-send-turn-policy.raw.jsonl",
                ["sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(rawPath))).ToLowerInvariant(),
            });
            File.WriteAllText(inventoryPath, inventory.ToJsonString());

            string localResultPath = Path.Combine(temporaryDirectory, "local-result.shadow.checksum.example.json");
            System.Text.Json.Nodes.JsonObject localResult =
                System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(localResultPath))!.AsObject();
            localResult["policyAxis"] = "application_send_turn_planning";
            localResult["mode"] = "forced";
            System.Text.Json.Nodes.JsonObject configuration = localResult["policyConfiguration"]!.AsObject();
            configuration["appliedPolicy"] = "not_applicable";
            configuration["forcedPolicy"] = null;
            configuration["shadowEnabled"] = false;
            configuration["shadowPolicy"] = null;
            configuration["ruleVersion"] = "application-send-turn-force-v1";
            configuration["observationContractVersion"] = "adaptive-runtime-application-send-turn-provenance-v1";
            localResult["treatments"]!["A"]!["policy"] = "legacy_current";
            localResult["treatments"]!["B"] = new System.Text.Json.Nodes.JsonObject
            {
                ["policy"] = "conservative",
                ["benchmarkBinaryRole"] = "candidate_benchmark",
                ["runtimeBinaryRole"] = "candidate_runtime",
            };
            localResult["samples"]![0]!["artifactPaths"]!.AsArray().Add(
                "fixture-artifacts/application-send-turn-policy.raw.jsonl");
            localResult["artifacts"]![0]!["sha256"] = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(inventoryPath))).ToLowerInvariant();
            File.WriteAllText(localResultPath, localResult.ToJsonString());

            string outputDirectory = Path.Combine(temporaryDirectory, "construction");
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult export =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1",
                    "-RawProvenancePath", rawPath,
                    "-OutputDirectory", outputDirectory,
                    "-DatasetId", "send-turn-test-dataset",
                    "-CampaignId", localResult["campaignId"]!.GetValue<string>(),
                    "-RunId", localResult["runId"]!.GetValue<string>(),
                    "-CellId", localResult["cellId"]!.GetValue<string>(),
                    "-SampleId", localResult["samples"]![0]!["sampleId"]!.GetValue<string>(),
                    "-ExpectedPolicy", "legacy_current",
                    "-BenchmarkSha256", new string('a', 64),
                    "-RuntimeSha256", new string('b', 64),
                    "-HostFingerprint", "test-host-fingerprint",
                    "-CorrectnessFlagsJson", "{\"payloadValid\":true,\"protocolValid\":true,\"timedOut\":false,\"ownershipValid\":true,\"terminalValid\":true,\"violationCodes\":[]}",
                    "-ScenarioId", "quic.transport.stream-throughput.1mb",
                    "-Connections", "1",
                    "-StreamsPerConnection", "1",
                    "-WarmupMicros", "0",
                    "-MeasurementMicros", "1000",
                    "-RepositoryRoot", repoRoot,
                    "-RepositoryCommit", "0123456789abcdef0123456789abcdef01234567");
            Assert.Equal(0, export.ExitCode);

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult validation =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1",
                    "-LocalResultPath", localResultPath,
                    "-ConstructionDatasetPath", Assert.Single(Directory.GetFiles(outputDirectory, "construction-row-*.json")));

            Assert.Equal(0, validation.ExitCode);
            using JsonDocument summary = JsonDocument.Parse(validation.Output);
            Assert.True(summary.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(1, summary.RootElement.GetProperty("constructionRowCount").GetInt32());
            Assert.Empty(summary.RootElement.GetProperty("failures").EnumerateArray());
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
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void LocalRunnerKeepsForcedConstructionAndShadowEpochEvidenceSeparate()
    {
        string runner = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1"));

        Assert.Contains("[ValidateSet('receive_credit_publication', 'application_send_turn_planning')]", runner, StringComparison.Ordinal);
        Assert.Contains("PROTOCOL_LAB_INCURSA_RAW_QUIC_APPLICATION_SEND_TURN_POLICY", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_APPLICATION_SEND_TURN_POLICY_CONTRACT=", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_APPLICATION_SEND_TURN_POLICY_JSON=", runner, StringComparison.Ordinal);
        Assert.Contains("application-send-turn-policy.raw.jsonl", runner, StringComparison.Ordinal);
        Assert.Contains("Convert-AdaptiveRuntimeApplicationSendTurnProvenance.ps1", runner, StringComparison.Ordinal);
        Assert.Contains("ConstructionDatasetPath = @($constructionRowPaths)", runner, StringComparison.Ordinal);
        Assert.Contains("$constructionArguments = [ordered]@{", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_APPLICATION_SEND_TURN_EVIDENCE_CONTRACT=", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_APPLICATION_SEND_TURN_EVIDENCE_JSON=", runner, StringComparison.Ordinal);
        Assert.Contains("application-send-turn-evidence.raw.jsonl", runner, StringComparison.Ordinal);
        Assert.Contains("Convert-AdaptiveRuntimeApplicationSendTurnEvidence.ps1", runner, StringComparison.Ordinal);
        Assert.Contains("EpochDatasetPath = @($epochRowPaths)", runner, StringComparison.Ordinal);
        Assert.Contains("$exportArguments = [ordered]@{", runner, StringComparison.Ordinal);
        Assert.Contains("application-send-turn-shadow-neutral-v1", runner, StringComparison.Ordinal);
        Assert.Contains("adaptive-runtime-application-send-turn-observation-v1", runner, StringComparison.Ordinal);
        Assert.Contains("[string[]] $shadowPolicies =", runner, StringComparison.Ordinal);
        Assert.Contains("[switch] $ObservationNeutrality", runner, StringComparison.Ordinal);
        Assert.Contains("A = 'disabled'; B = 'observe_only'", runner, StringComparison.Ordinal);
        Assert.Contains("if ($hostPolicy -eq 'unset') { $null } else { $hostPolicy }", runner, StringComparison.Ordinal);
        Assert.Contains("$isApplicationSendTurnEvidenceCampaign", runner, StringComparison.Ordinal);
        Assert.Contains("observe_only evidence contained a recommendation", runner, StringComparison.Ordinal);
        Assert.Contains("disabled observation emitted application-send-turn evidence", runner, StringComparison.Ordinal);
        Assert.Contains("if ($isApplicationSendTurnAxis -and -not $ShadowOnly -and -not $ObservationNeutrality)", runner, StringComparison.Ordinal);
        Assert.Contains("$validationArguments = [ordered]@{ LocalResultPath = $resultPath }", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("application_send_turn_planning does not have shadow behavior yet", runner, StringComparison.Ordinal);
        Assert.Contains("policy_mismatch", runner, StringComparison.Ordinal);
        Assert.Contains("policyAxis = $PolicyAxis", runner, StringComparison.Ordinal);
        Assert.DoesNotContain("mode = 'active_internal'", runner, StringComparison.OrdinalIgnoreCase);
    }

    private static void CopyDirectory(string sourceDirectory, string destinationDirectory)
    {
        foreach (string sourcePath in Directory.GetFiles(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            string relativePath = Path.GetRelativePath(sourceDirectory, sourcePath);
            string destinationPath = Path.Combine(destinationDirectory, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
            File.Copy(sourcePath, destinationPath, overwrite: true);
        }
    }
}
