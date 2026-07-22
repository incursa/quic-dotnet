// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0172")]
public sealed class REQ_QUIC_CRT_0172
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatorAcceptsChecksumBackedJoinedEvidence()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
            "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1",
            "-LocalResultPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json"),
            "-EpochDatasetPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json"));

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.True(root.GetProperty("valid").GetBoolean());
        Assert.Equal(1, root.GetProperty("checksumInventoryCount").GetInt32());
        Assert.Equal(1, root.GetProperty("uniqueEpochRowCount").GetInt32());
        Assert.Empty(root.GetProperty("failures").EnumerateArray());

        using JsonDocument localResult = AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json");
        JsonElement resultRoot = localResult.RootElement;
        JsonElement aggregateOutcomes = resultRoot.GetProperty("aggregateOutcomes");
        Assert.Equal(JsonValueKind.Null, aggregateOutcomes.GetProperty("allocatedBytes").ValueKind);
        Assert.Equal(JsonValueKind.Null, aggregateOutcomes.GetProperty("peakRetainedBytes").ValueKind);
        Assert.Equal(131072, aggregateOutcomes.GetProperty("bufferPoolRentedBytes").GetInt32());
        Assert.Equal(65536, aggregateOutcomes.GetProperty("bufferPoolOutstandingPeakBytes").GetInt32());
        JsonElement fairness = resultRoot.GetProperty("fairnessOutcomes");
        Assert.False(fairness.GetProperty("assessed").GetBoolean());
        Assert.Equal(JsonValueKind.Null, fairness.GetProperty("streamCompletionP95Ms").ValueKind);
        Assert.Equal(JsonValueKind.Null, fairness.GetProperty("streamCompletionP99Ms").ValueKind);
        Assert.Equal(0, fairness.GetProperty("starvationCount").GetInt32());
    }

    [Theory]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.sample-missing.example.json", "does not resolve to source sample")]
    [InlineData("tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.exclusion-mismatch.example.json", "missing required analysis exclusion flag 'observation_missing'")]
    [InlineData("tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum-join-missing.example.json", "source artifact is missing from checksum inventory")]
    public void ValidatorRejectsBrokenSampleJoinExclusionAndChecksumEvidence(string epochRowRelativePath, string expectedFailure)
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
            "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1",
            "-LocalResultPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json"),
            "-EpochDatasetPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(epochRowRelativePath));

        Assert.NotEqual(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.False(root.GetProperty("valid").GetBoolean());
        Assert.Contains(
            root.GetProperty("failures").EnumerateArray().Select(static failure => failure.GetString()!).ToArray(),
            failure => failure.Contains(expectedFailure, StringComparison.Ordinal));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ValidatorRejectsDuplicateRowIdsWithinOneJoinedEvidenceSet()
    {
        string scriptPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1");
        string resultPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json");
        string firstRowPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json");
        string duplicateRowPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.duplicate-row-id.example.json");
        string command = $"& {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(scriptPath)} " +
            $"-LocalResultPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(resultPath)} " +
            $"-EpochDatasetPath @({AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(firstRowPath)}," +
            $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(duplicateRowPath)})";
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellCommand(command);

        Assert.NotEqual(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.False(root.GetProperty("valid").GetBoolean());
        Assert.Equal(1, root.GetProperty("uniqueEpochRowCount").GetInt32());
        Assert.Contains(
            root.GetProperty("failures").EnumerateArray().Select(static failure => failure.GetString()!).ToArray(),
            failure => failure.Contains("Duplicate epoch-row rowId", StringComparison.Ordinal));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidatorRejectsTamperedChecksumInventoryBeforeUsingItAsTrustRoot()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string sourceDirectory = Path.GetDirectoryName(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json"))!;
        string temporaryDirectory = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"tampered-inventory-test-{Guid.NewGuid():N}");

        try
        {
            CopyDirectory(sourceDirectory, temporaryDirectory);
            File.AppendAllText(Path.Combine(temporaryDirectory, "checksum-inventory.shadow.example.json"), " ");

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1",
                "-LocalResultPath", Path.Combine(temporaryDirectory, "local-result.shadow.checksum.example.json"),
                "-EpochDatasetPath", Path.Combine(temporaryDirectory, "epoch-row.shadow.checksum.example.json"));

            Assert.NotEqual(0, result.ExitCode);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.Contains(
                summary.RootElement.GetProperty("failures").EnumerateArray().Select(static failure => failure.GetString()!).ToArray(),
                failure => failure.Contains("recorded checksum inventory sha256", StringComparison.Ordinal));
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
    public void ValidatorRejectsPopulatedOutcomeMetricsThatDoNotMatchRetainedArtifacts()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
            "eng/adaptive-runtime/Test-AdaptiveRuntimePolicyEvidence.ps1",
            "-LocalResultPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.outcome-mismatch.example.json"),
            "-EpochDatasetPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json"));

        Assert.NotEqual(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        Assert.Contains(
            summary.RootElement.GetProperty("failures").EnumerateArray().Select(static failure => failure.GetString()!).ToArray(),
            failure => failure.Contains("outcomes.bufferPoolRentedBytes does not match quic-buffer-pool-summary.json", StringComparison.Ordinal));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DatasetPipelinePreservesMissingMetricsAndProducesBlockedHoldoutManifest()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string outputRoot = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"pipeline-test-{Guid.NewGuid():N}");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Invoke-AdaptiveRuntimeDatasetPipeline.ps1",
                "-LocalResultPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json"),
                "-EpochDatasetPath", AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json"),
                "-OutputRoot", outputRoot,
                "-DatasetId", "adaptive-runtime-pipeline-test",
                "-DatasetVersion", "test-v1");

            Assert.Equal(0, result.ExitCode);
            string normalizedPath = Path.Combine(outputRoot, "normalized", "normalized-dataset.json");
            string curatedPath = Path.Combine(outputRoot, "curated", "curated-manifest.json");
            string splitPath = Path.Combine(outputRoot, "split", "split-manifest.json");
            Assert.True(File.Exists(normalizedPath));
            Assert.True(File.Exists(curatedPath));
            Assert.True(File.Exists(splitPath));

            using JsonDocument normalized = JsonDocument.Parse(File.ReadAllText(normalizedPath));
            JsonElement metrics = normalized.RootElement.GetProperty("rows")[0].GetProperty("normalizedMetrics");
            Assert.Equal(JsonValueKind.Null, metrics.GetProperty("throughputMiBPerSecond").ValueKind);
            Assert.Equal(JsonValueKind.Null, metrics.GetProperty("allocatedKiB").ValueKind);
            Assert.Equal(JsonValueKind.Null, metrics.GetProperty("peakRetainedKiB").ValueKind);
            Assert.Equal(JsonValueKind.Null, metrics.GetProperty("queueToServiceRatio").ValueKind);
            Assert.Equal(JsonValueKind.Null, metrics.GetProperty("flowBlockedMs").ValueKind);

            using JsonDocument curated = JsonDocument.Parse(File.ReadAllText(curatedPath));
            Assert.Equal("excluded", curated.RootElement.GetProperty("rowDecisions")[0].GetProperty("decision").GetString());

            using JsonDocument split = JsonDocument.Parse(File.ReadAllText(splitPath));
            Assert.Equal("insufficient_group_diversity", split.RootElement.GetProperty("status").GetString());
            Assert.Equal("holdout_blocked", split.RootElement.GetProperty("assignments")[0].GetProperty("split").GetString());
        }
        finally
        {
            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, recursive: true);
            }
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DatasetPipelineRetainsUnmatchedEpochRowsWithReasonCodes()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string outputRoot = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"pipeline-unmatched-test-{Guid.NewGuid():N}");
        string scriptPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/adaptive-runtime/Invoke-AdaptiveRuntimeDatasetPipeline.ps1");
        string resultPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/local-result.shadow.checksum.example.json");
        string joinedRowPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.checksum.example.json");
        string unmatchedRowPath = AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "tests/fixtures/adaptive-runtime-policy/epoch-row.shadow.sample-missing.example.json");
        string command = $"& {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(scriptPath)} " +
            $"-LocalResultPath {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(resultPath)} " +
            $"-EpochDatasetPath @({AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(joinedRowPath)}," +
            $"{AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(unmatchedRowPath)}) " +
            $"-OutputRoot {AdaptiveRuntimePolicyScriptTestSupport.QuotePowerShellLiteral(outputRoot)} " +
            "-DatasetId adaptive-runtime-unmatched-test -DatasetVersion test-v1";

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellCommand(command);

            Assert.Equal(0, result.ExitCode);
            using JsonDocument normalized = JsonDocument.Parse(
                File.ReadAllText(Path.Combine(outputRoot, "normalized", "normalized-dataset.json")));
            JsonElement root = normalized.RootElement;
            Assert.Single(root.GetProperty("rows").EnumerateArray());
            JsonElement unmatched = Assert.Single(root.GetProperty("unmatchedEpochRows").EnumerateArray());
            Assert.Equal("unmatched_epoch_row", unmatched.GetProperty("reasonCode").GetString());
            Assert.Equal(1, root.GetProperty("summary").GetProperty("unmatchedEpochRowCount").GetInt32());
        }
        finally
        {
            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, recursive: true);
            }
        }
    }

    private static void CopyDirectory(string sourceDirectory, string destinationDirectory)
    {
        foreach (string directory in Directory.EnumerateDirectories(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(Path.Combine(destinationDirectory, Path.GetRelativePath(sourceDirectory, directory)));
        }

        Directory.CreateDirectory(destinationDirectory);
        foreach (string file in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.AllDirectories))
        {
            string destination = Path.Combine(destinationDirectory, Path.GetRelativePath(sourceDirectory, file));
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Copy(file, destination);
        }
    }
}
