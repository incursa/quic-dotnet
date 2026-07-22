// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0171")]
public sealed class REQ_QUIC_CRT_0171
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PhaseTransitionFixtureRetainsReviewOnlyRecoveryPhaseAndCommandLineage()
    {
        using JsonDocument fixture = AdaptiveRuntimePolicyScriptTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/phase-transition-schedule.example.json");

        JsonElement root = fixture.RootElement;
        Assert.Equal("adaptive-runtime-policy-phase-transition-schedule-v1", root.GetProperty("schemaVersion").GetString());
        Assert.Equal("independent_cell_sequence", root.GetProperty("executionModel").GetString());
        Assert.Equal("not_supported", root.GetProperty("sameConnectionPhaseExecution").GetString());
        Assert.Equal("few_to_many_to_few_review_artifact", root.GetProperty("transitionIntent").GetString());

        JsonElement recoveryPhase = root.GetProperty("phases")[5];
        Assert.Equal("planned_only", recoveryPhase.GetProperty("executionStatus").GetString());
        Assert.Contains("same-connection phased executor", recoveryPhase.GetProperty("gating").GetString(), StringComparison.Ordinal);

        JsonElement commandLineage = root.GetProperty("commandLineage");
        Assert.Contains("Invoke-AdaptiveRuntimePolicyLocalSchedule.ps1", commandLineage.GetProperty("scheduleScriptPath").GetString(), StringComparison.Ordinal);
        Assert.Contains("Invoke-AdaptiveRuntimePolicyLocalCell.ps1", commandLineage.GetProperty("cellRunnerPath").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DryRunWritesPhaseTransitionArtifactWithoutClaimingSameConnectionExecution()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string campaignId = $"adaptive-runtime-dryrun-test-{Guid.NewGuid():N}";
        string artifactRoot = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", campaignId);
        string artifactPath = Path.Combine(artifactRoot, "phase-transition-schedule.json");
        string missingProtocolLabRoot = Path.Combine(repoRoot, ".missing", "protocol-lab");
        string missingProtocolLabExecutionRoot = Path.Combine(repoRoot, ".missing", "protocol-lab-internal");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Invoke-AdaptiveRuntimePolicyLocalSchedule.ps1",
                "-CampaignId", campaignId,
                "-ScheduleProfile", "balanced",
                "-ProtocolLabRoot", missingProtocolLabRoot,
                "-ProtocolLabExecutionRoot", missingProtocolLabExecutionRoot,
                "-DryRun");

            Assert.Equal(0, result.ExitCode);
            Assert.Contains("phase transition artifact:", result.Output, StringComparison.Ordinal);
            Assert.True(File.Exists(artifactPath), $"Expected dry-run phase-transition artifact at '{artifactPath}'.");

            using JsonDocument artifact = JsonDocument.Parse(File.ReadAllText(artifactPath));
            JsonElement root = artifact.RootElement;
            Assert.Equal("adaptive-runtime-policy-phase-transition-schedule-v1", root.GetProperty("schemaVersion").GetString());
            Assert.Equal("independent_cell_sequence", root.GetProperty("executionModel").GetString());
            Assert.Equal("not_supported", root.GetProperty("sameConnectionPhaseExecution").GetString());
            Assert.False(root.GetProperty("activePolicyAuthorized").GetBoolean());
            Assert.False(root.GetProperty("onlineLearningAuthorized").GetBoolean());
            Assert.False(root.GetProperty("protocolLabSubmissionAuthorized").GetBoolean());

            JsonElement phases = root.GetProperty("phases");
            Assert.Equal("adaptive-runtime.connection-wave.upload.v1", phases[0].GetProperty("phaseId").GetString());
            Assert.Equal("planned_only", phases[5].GetProperty("executionStatus").GetString());
            Assert.Contains("same-connection phased executor", phases[5].GetProperty("gating").GetString(), StringComparison.Ordinal);

            JsonElement commandLineage = root.GetProperty("commandLineage");
            Assert.Equal(missingProtocolLabRoot, commandLineage.GetProperty("protocolLabRoot").GetString());
            Assert.Equal(missingProtocolLabExecutionRoot, commandLineage.GetProperty("protocolLabExecutionRoot").GetString());
            Assert.True(commandLineage.GetProperty("cells").GetArrayLength() >= 5);
        }
        finally
        {
            if (Directory.Exists(artifactRoot))
            {
                Directory.Delete(artifactRoot, recursive: true);
            }
        }
    }
}
