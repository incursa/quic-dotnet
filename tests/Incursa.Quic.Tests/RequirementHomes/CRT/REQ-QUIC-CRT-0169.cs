// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0169")]
public sealed class REQ_QUIC_CRT_0169
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CanonicalExamplesCarryJoinedVersionedProvenance()
    {
        using JsonDocument result = ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.example.json");
        using JsonDocument epoch = ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.example.json");
        JsonElement resultRoot = result.RootElement;
        JsonElement epochRoot = epoch.RootElement;
        JsonElement policyConfiguration = resultRoot.GetProperty("policyConfiguration");
        JsonElement provenance = epochRoot.GetProperty("provenance");

        Assert.Equal("adaptive-runtime-policy-local-result-v1", resultRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal("adaptive-runtime-policy-epoch-dataset-v1", epochRoot.GetProperty("schemaVersion").GetString());
        Assert.Equal(resultRoot.GetProperty("runId").GetString(), epochRoot.GetProperty("runId").GetString());
        Assert.Equal(resultRoot.GetProperty("campaignId").GetString(), epochRoot.GetProperty("campaignId").GetString());
        Assert.Equal(resultRoot.GetProperty("cellId").GetString(), epochRoot.GetProperty("cellId").GetString());
        Assert.Equal(
            policyConfiguration.GetProperty("ruleVersion").GetString(),
            provenance.GetProperty("ruleVersion").GetString());
        Assert.Equal(
            policyConfiguration.GetProperty("observationContractVersion").GetString(),
            provenance.GetProperty("observationContractVersion").GetString());
        Assert.Equal(64, provenance.GetProperty("benchmarkSha256").GetString()!.Length);
        Assert.Equal(64, provenance.GetProperty("runtimeSha256").GetString()!.Length);
        Assert.Equal(64, provenance.GetProperty("sourceArtifactSha256").GetString()!.Length);
        JsonElement targetAttribution = resultRoot.GetProperty("samples")[0].GetProperty("targetAttribution");
        Assert.Equal(4100, targetAttribution.GetProperty("rootProcessId").GetInt32());
        Assert.Equal(4101, targetAttribution.GetProperty("resolvedProcessId").GetInt32());
        Assert.Equal(4101, targetAttribution.GetProperty("measuredProcessId").GetInt32());
        Assert.Equal(4101, targetAttribution.GetProperty("counterProcessId").GetInt32());
        Assert.Equal("adapter-process-metrics", targetAttribution.GetProperty("resolutionStrategy").GetString());
        Assert.Equal("adapter-resolved-live-process", targetAttribution.GetProperty("measurementSource").GetString());
        Assert.True(targetAttribution.GetProperty("resolvedEqualsMeasured").GetBoolean());
        Assert.True(targetAttribution.GetProperty("resolvedEqualsCounter").GetBoolean());
        Assert.True(targetAttribution.GetProperty("valid").GetBoolean());
        Assert.True(epochRoot
            .GetProperty("workloadAnalysisOnly")
            .GetProperty("excludedFromProductionFeatures")
            .GetBoolean());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedExamplesRecordTheActualForcedPolicyAndShadowRecommendation()
    {
        using JsonDocument result = ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/local-result.forced.example.json");
        using JsonDocument epoch = ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.forced.example.json");

        JsonElement resultRoot = result.RootElement;
        JsonElement epochRoot = epoch.RootElement;
        JsonElement policyConfiguration = resultRoot.GetProperty("policyConfiguration");
        JsonElement candidatePolicySelection = epochRoot.GetProperty("candidatePolicySelection");

        Assert.Equal("forced", resultRoot.GetProperty("mode").GetString());
        Assert.Equal("immediate", policyConfiguration.GetProperty("appliedPolicy").GetString());
        Assert.Equal("immediate", policyConfiguration.GetProperty("forcedPolicy").GetString());
        Assert.False(policyConfiguration.GetProperty("shadowEnabled").GetBoolean());
        Assert.Equal("read_dominant_batch", policyConfiguration.GetProperty("shadowPolicy").GetString());
        Assert.Equal("forced", candidatePolicySelection.GetProperty("selectionSource").GetString());
        Assert.Equal("immediate", candidatePolicySelection.GetProperty("selectedPolicy").GetString());
        Assert.Equal("read_dominant_batch", candidatePolicySelection.GetProperty("shadowRecommendation").GetString());
        Assert.Equal("immediate", epochRoot.GetProperty("currentPolicyState").GetProperty("appliedPolicy").GetString());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EpochSchemaRequiresImmutableSourceAndTransformationIdentity()
    {
        using JsonDocument schema = ReadRepositoryJson(
            "schemas/adaptive-runtime-policy-epoch-dataset-v1.schema.json");
        JsonElement definitions = schema.RootElement.GetProperty("$defs");
        HashSet<string> provenanceRequirements = definitions
            .GetProperty("provenance")
            .GetProperty("required")
            .EnumerateArray()
            .Select(static item => item.GetString()!)
            .ToHashSet(StringComparer.Ordinal);
        HashSet<string> transformationRequirements = definitions
            .GetProperty("provenance")
            .GetProperty("properties")
            .GetProperty("transformation")
            .GetProperty("required")
            .EnumerateArray()
            .Select(static item => item.GetString()!)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains("repositoryCommit", provenanceRequirements);
        Assert.Contains("benchmarkSha256", provenanceRequirements);
        Assert.Contains("runtimeSha256", provenanceRequirements);
        Assert.Contains("sourceArtifactSha256", provenanceRequirements);
        Assert.Contains("resultSchemaVersion", provenanceRequirements);
        Assert.Contains("datasetSchemaVersion", provenanceRequirements);
        Assert.Contains("ruleVersion", provenanceRequirements);
        Assert.Contains("observationContractVersion", provenanceRequirements);
        Assert.Equal(
            ["codeCommit", "inputSha256", "name", "outputSha256", "version"],
            transformationRequirements.Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeObservationProhibitsTransportAndApplicationIdentity()
    {
        string[] propertyNames = typeof(QuicAdaptiveRuntimeConnectionObservation)
            .GetProperties()
            .Select(static property => property.Name)
            .ToArray();

        Assert.DoesNotContain("ConnectionId", propertyNames);
        Assert.DoesNotContain("StreamId", propertyNames);
        Assert.DoesNotContain("PeerAddress", propertyNames);
        Assert.DoesNotContain("Url", propertyNames);
        Assert.DoesNotContain("ApplicationId", propertyNames);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PermanentLocalCellRunnerPreservesForcedSequenceAndProvenanceGates()
    {
        string runner = ReadRepositoryText(
            "eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalCell.ps1");

        Assert.Contains("@('A', 'B', 'B', 'A')", runner, StringComparison.Ordinal);
        Assert.Contains("@('B', 'A', 'A', 'B')", runner, StringComparison.Ordinal);
        Assert.Contains("PROTOCOL_LAB_INCURSA_RAW_QUIC_RECEIVE_CREDIT_POLICY", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_RECEIVE_CREDIT_POLICY=", runner, StringComparison.Ordinal);
        Assert.Contains("adapter-artifacts.json", runner, StringComparison.Ordinal);
        Assert.Contains("campaign-host.stdout.log", runner, StringComparison.Ordinal);
        Assert.Contains("a frozen campaign binary changed during the sequence", runner, StringComparison.Ordinal);
        Assert.Contains("Campaign output already exists and will not be rewritten", runner, StringComparison.Ordinal);
        Assert.Contains("Get-ScenarioShape", runner, StringComparison.Ordinal);
        Assert.Contains("requires payloadBytes=", runner, StringComparison.Ordinal);
        Assert.Contains("Exactly one treatment must be legacy_current", runner, StringComparison.Ordinal);
        Assert.Contains("Get-RelativeRange", runner, StringComparison.Ordinal);
        Assert.Contains("maximumWithinTreatmentRelativeRange", runner, StringComparison.Ordinal);
        Assert.Contains("Test-Json -SchemaFile $resultSchemaPath", runner, StringComparison.Ordinal);
        Assert.Contains("[switch] $ShadowOnly", runner, StringComparison.Ordinal);
        Assert.Contains("[switch] $StressOnly", runner, StringComparison.Ordinal);
        Assert.Contains("elseif ($StressOnly)", runner, StringComparison.Ordinal);
        Assert.Contains("QUIC_ADAPTIVE_RUNTIME_EPOCH_JSON=", ReadRepositoryText(
            "eng/protocol-lab/servers/IncursaRawQuicServer/Program.cs"), StringComparison.Ordinal);
        Assert.Contains("adaptive-runtime-connection-observation-v1", runner, StringComparison.Ordinal);
        Assert.Contains("Test-AdaptiveRuntimePolicyEvidence.ps1", runner, StringComparison.Ordinal);
        Assert.Contains("'-CaptureCounters'", runner, StringComparison.Ordinal);
        Assert.Contains("counters-summary.json", runner, StringComparison.Ordinal);
        Assert.Contains("counters-summary.json was not retained", runner, StringComparison.Ordinal);
        Assert.Contains("targetAttribution", runner, StringComparison.Ordinal);
        Assert.Contains("resolvedEqualsCounter", runner, StringComparison.Ordinal);
        Assert.Contains("runner-counter-attach-resolved-process", runner, StringComparison.Ordinal);
        Assert.Contains("[AllowEmptyCollection()]", runner, StringComparison.Ordinal);
        Assert.Contains("selectionSource = if ($ShadowOnly) { 'shadow_rule' } else { 'forced' }", runner, StringComparison.Ordinal);
        Assert.Contains("policy_mismatch", runner, StringComparison.Ordinal);
        Assert.Contains("$exclusionFlags.Add('target_health_invalid')", runner, StringComparison.Ordinal);
        Assert.Contains("$exclusionFlags.Add('generator_health_invalid')", runner, StringComparison.Ordinal);
        Assert.Contains("$exclusionFlags.Add('correctness_failed')", runner, StringComparison.Ordinal);
        Assert.Contains("if ($epochRowPaths.Count -gt 0)", runner, StringComparison.Ordinal);
        string validator = ReadRepositoryText("eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1");
        Assert.Contains("source sample treatment", validator, StringComparison.Ordinal);
        string readme = ReadRepositoryText("eng/adaptive-runtime/README.md")
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal);
        Assert.Contains("Host/process counters are captured for every sample so forced-policy evidence keeps a pressure artifact by default.", readme, StringComparison.Ordinal);
        Assert.Contains("Every forced-policy sample also retains `counters-summary.json` as the result's pressure artifact", readme, StringComparison.Ordinal);
        Assert.Contains("retains per-sample target attribution proving root, resolved, measured, and counter PID alignment", readme, StringComparison.Ordinal);
        Assert.Contains("adaptive-runtime-epochs.raw.jsonl", readme, StringComparison.Ordinal);
        Assert.DoesNotContain("mode = 'active_internal'", runner, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-QuicDotNetProtocolLabRun.ps1", runner, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PermanentLocalScheduleDeclaresVariedHigherCountCellsWithoutAuthorizingRuntimeSelection()
    {
        string schedule = ReadRepositoryText(
            "eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalSchedule.ps1");

        Assert.Contains("[ValidateSet('balanced', 'connection_first', 'stream_first')]", schedule, StringComparison.Ordinal);
        Assert.Contains("quic.transport.stream-throughput.1mb", schedule, StringComparison.Ordinal);
        Assert.Contains("quic.transport.stream-download.1mb", schedule, StringComparison.Ordinal);
        Assert.Contains("quic.transport.duplex-streams-peer-matrix", schedule, StringComparison.Ordinal);
        Assert.Contains("quic.transport.multiplex.100x1kb", schedule, StringComparison.Ordinal);
        Assert.Contains("-Connections 16", schedule, StringComparison.Ordinal);
        Assert.Contains("-Connections 32", schedule, StringComparison.Ordinal);
        Assert.Contains("-StreamsPerConnection 100", schedule, StringComparison.Ordinal);
        Assert.Contains("StressOnly = [bool] $cell.stressOnly", schedule, StringComparison.Ordinal);
        Assert.Contains("if (($index % 2) -eq 0) { 'ABBA' } else { 'BAAB' }", schedule, StringComparison.Ordinal);
        Assert.Contains("counterCaptureRequired = $true", schedule, StringComparison.Ordinal);
        Assert.Contains("A permanent measurement runner changed before resume", schedule, StringComparison.Ordinal);
        Assert.Contains("The retained measurement cells changed before resume", schedule, StringComparison.Ordinal);
        Assert.Contains("Resume parameters do not match the retained measurement schedule", schedule, StringComparison.Ordinal);
        Assert.Contains("continueOnFailure = [bool] $ContinueOnFailure", schedule, StringComparison.Ordinal);
        Assert.Contains("retained_terminal_failure", schedule, StringComparison.Ordinal);
        Assert.Contains("terminal_failure_retained", schedule, StringComparison.Ordinal);
        Assert.Contains("retained_incomplete_artifacts", schedule, StringComparison.Ordinal);
        Assert.Contains("activePolicyAuthorized = $false", schedule, StringComparison.Ordinal);
        Assert.Contains("onlineLearningAuthorized = $false", schedule, StringComparison.Ordinal);
        Assert.Contains("protocolLabSubmissionAuthorized = $false", schedule, StringComparison.Ordinal);
        Assert.Contains("Invoke-AdaptiveRuntimePolicyLocalCell.ps1", schedule, StringComparison.Ordinal);
        Assert.DoesNotContain("active_internal", schedule, StringComparison.OrdinalIgnoreCase);
    }

    private static JsonDocument ReadRepositoryJson(string relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Unable to locate repository file '{relativePath}'.");
    }

    private static string ReadRepositoryText(string relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                return File.ReadAllText(candidate);
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Unable to locate repository file '{relativePath}'.");
    }
}
