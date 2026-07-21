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
        Assert.True(epochRoot
            .GetProperty("workloadAnalysisOnly")
            .GetProperty("excludedFromProductionFeatures")
            .GetBoolean());
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
        Assert.DoesNotContain("mode = 'active_internal'", runner, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Invoke-QuicDotNetProtocolLabRun.ps1", runner, StringComparison.OrdinalIgnoreCase);
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
