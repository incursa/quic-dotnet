// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

public sealed partial class REQ_QUIC_CRT_0177
{
    [Fact]
    public void UnifiedSnapshotAcceptsFourLegacyAxesInCanonicalOrder()
    {
        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));

        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.ApplicationSendTurnPlanning.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.ApplicationSendBatchFormation.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.QueuedSendBurstBudget.AppliedValue);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.OversizedWriteAdmissionQuantum.AppliedValue);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 2)]
    [InlineData(2, 3)]
    [InlineData(3, 4)]
    [InlineData(3, 5)]
    public void UnifiedSnapshotAcceptsExactlyOneForcedAxis(
        int forcedAxisValue,
        int forcedPolicyValue)
    {
        QuicAdaptiveRuntimeStage1Axis forcedAxis =
            (QuicAdaptiveRuntimeStage1Axis)forcedAxisValue;
        QuicAdaptiveRuntimeStage1PolicyValue forcedValue =
            (QuicAdaptiveRuntimeStage1PolicyValue)forcedPolicyValue;
        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = CreateSnapshot(
            forcedAxis,
            forcedValue);

        QuicAdaptiveRuntimeStage1AxisDecision forced = forcedAxis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                snapshot.ApplicationSendTurnPlanning,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                snapshot.ApplicationSendBatchFormation,
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                snapshot.QueuedSendBurstBudget,
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                snapshot.OversizedWriteAdmissionQuantum,
            _ => throw new ArgumentOutOfRangeException(nameof(forcedAxis)),
        };

        Assert.True(forced.HasForcedValue);
        Assert.Equal(forcedValue, forced.AppliedValue);
    }

    [Fact]
    public void UnifiedSnapshotRejectsDuplicateOrOutOfOrderAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision sendTurn =
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning);

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            sendTurn,
            sendTurn,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRejectsMultipleForcedAxes()
    {
        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
                QuicAdaptiveRuntimeStage1PolicyValue.Conservative),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRejectsNonLegacyAdjacentAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalidAdjacent = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget) with
        {
            SelectedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            invalidAdjacent,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotRequiresForcedAndAppliedIdentityToMatch()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalidForced = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible) with
        {
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            invalidForced,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedSnapshotAllowsNamedSafetyOverrideOfForcedValue()
    {
        QuicAdaptiveRuntimeStage1AxisDecision guarded = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
            QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram) with
        {
            AppliedValue = QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            SelectionSource = QuicAdaptiveRuntimeStage1SelectionSource.SafetyOverride,
            SafetyOverrideReason = QuicAdaptiveRuntimeStage1SafetyOverrideReason.Recovery,
        };

        QuicAdaptiveRuntimeStage1PolicySnapshot snapshot = new(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation),
            guarded,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum));

        Assert.True(snapshot.QueuedSendBurstBudget.SafetyOverrideApplied);
        Assert.Equal(
            QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            snapshot.QueuedSendBurstBudget.AppliedValue);
    }

    [Fact]
    public void UnifiedSnapshotRejectsPolicyValueFromAnotherAxis()
    {
        QuicAdaptiveRuntimeStage1AxisDecision invalid = CreateDecision(
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation) with
        {
            SelectedValue = QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
        };

        Assert.Throws<ArgumentException>(() => new QuicAdaptiveRuntimeStage1PolicySnapshot(
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning),
            invalid,
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget),
            CreateDecision(QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum)));
    }

    [Fact]
    public void UnifiedEvidenceValidatorAcceptsExactFourAxisJoin()
    {
        AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
            AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1",
                "-UnifiedEpochPath",
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-unified-epoch.valid.example.json"),
                "-AxisDecisionPath",
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-axis-decisions.valid.example.json"));

        Assert.Equal(0, result.ExitCode);
        using JsonDocument summary = JsonDocument.Parse(result.Output);
        JsonElement root = summary.RootElement;
        Assert.True(root.GetProperty("valid").GetBoolean());
        Assert.Equal(1, root.GetProperty("unifiedEpochRowCount").GetInt32());
        Assert.Equal(4, root.GetProperty("axisRecordCount").GetInt32());
        Assert.Equal(4, root.GetProperty("axisDecisionRowCount").GetInt32());
        Assert.Equal(
            1,
            root.GetProperty("variedAxisEpochCounts")
                .GetProperty("application_send_batch_formation")
                .GetInt32());
    }

    [Fact]
    public void UnifiedEvidenceValidatorAcceptsHonestEpochSummaryJoins()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-unified-epoch-summary-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            JsonObject row = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-unified-epoch.valid.example.json")))!.AsObject();
            foreach (JsonNode? axisRecord in row["axisRecords"]!.AsArray())
            {
                axisRecord!["latch"]!["operationKey"] = null;
                axisRecord["latch"]!["planKey"] = null;
            }

            JsonArray decisions = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-axis-decisions.valid.example.json")))!.AsArray();
            foreach (JsonNode? decision in decisions)
            {
                decision!["recordKind"] = "epoch_summary";
                decision["operationKey"] = null;
                decision["planKey"] = null;
            }

            string rowPath =
                Path.Combine(temporaryDirectory, "epoch-summary-row.json");
            string decisionPath =
                Path.Combine(temporaryDirectory, "epoch-summary-decisions.json");
            File.WriteAllText(rowPath, row.ToJsonString());
            File.WriteAllText(decisionPath, decisions.ToJsonString());

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1",
                    "-UnifiedEpochPath",
                    rowPath,
                    "-AxisDecisionPath",
                    decisionPath);

            Assert.True(result.ExitCode == 0, result.Output);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.True(summary.RootElement.GetProperty("valid").GetBoolean());
            Assert.Equal(
                4,
                summary.RootElement.GetProperty("axisDecisionRowCount").GetInt32());
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void UnifiedEvidenceValidatorRejectsNonLegacyAdjacentAxis()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-unified-validator-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            JsonObject row = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-unified-epoch.valid.example.json")))!.AsObject();
            JsonObject adjacentBurstAxis = row["axisRecords"]![2]!.AsObject();
            adjacentBurstAxis["selectedValue"] = "single_datagram";
            adjacentBurstAxis["appliedValue"] = "single_datagram";
            string rowPath = Path.Combine(temporaryDirectory, "invalid-adjacent-axis.json");
            File.WriteAllText(rowPath, row.ToJsonString());

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1",
                "-UnifiedEpochPath",
                rowPath,
                "-AxisDecisionPath",
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-axis-decisions.valid.example.json"));

            Assert.NotEqual(0, result.ExitCode);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.Contains(
                summary.RootElement.GetProperty("failures")
                    .EnumerateArray()
                    .Select(static failure => failure.GetString()!),
                failure => failure.Contains(
                    "unforced axis 'queued_send_burst_budget' applied 'single_datagram'",
                    StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Fact]
    public void UnifiedEvidenceValidatorRejectsDecisionJoinDrift()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-unified-join-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            JsonArray decisions = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-axis-decisions.valid.example.json")))!.AsArray();
            decisions[1]!["decisionSequence"] = 99;
            string decisionPath = Path.Combine(temporaryDirectory, "invalid-decision-join.json");
            File.WriteAllText(decisionPath, decisions.ToJsonString());

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1",
                    "-UnifiedEpochPath",
                    AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                        "tests/fixtures/adaptive-runtime-policy/stage1-unified-epoch.valid.example.json"),
                    "-AxisDecisionPath",
                    decisionPath);

            Assert.NotEqual(0, result.ExitCode);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.Contains(
                summary.RootElement.GetProperty("failures")
                    .EnumerateArray()
                    .Select(static failure => failure.GetString()!),
                failure => failure.Contains(
                    "does not resolve to a unified epoch axis record",
                    StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    [Theory]
    [InlineData("invalid_axis_value", "recorded invalid forcedValue 'single_datagram'")]
    [InlineData("multiple_forced", "forced 2 Stage 1 axes")]
    [InlineData("safety_source", "marked safetyOverride.applied=true without selectionSource='safety_override'")]
    [InlineData("record_kind_key", "recorded recordKind 'packet_plan' instead of 'actor_turn'")]
    public void UnifiedEvidenceValidatorRejectsSemanticContractDrift(
        string mutation,
        string expectedFailure)
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string temporaryDirectory = Path.Combine(
            repoRoot,
            ".artifacts",
            "adaptive-runtime",
            $"stage1-unified-semantic-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryDirectory);

        try
        {
            JsonObject row = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-unified-epoch.valid.example.json")))!.AsObject();
            JsonArray decisions = JsonNode.Parse(File.ReadAllText(
                AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
                    "tests/fixtures/adaptive-runtime-policy/stage1-axis-decisions.valid.example.json")))!.AsArray();

            switch (mutation)
            {
                case "invalid_axis_value":
                    foreach (string property in new[] { "forcedValue", "selectedValue", "appliedValue" })
                    {
                        row["axisRecords"]![1]![property] = "single_datagram";
                        decisions[1]![property] = "single_datagram";
                    }
                    break;
                case "multiple_forced":
                    row["axisRecords"]![2]!["forcedValue"] = "single_datagram";
                    row["axisRecords"]![2]!["selectedValue"] = "single_datagram";
                    row["axisRecords"]![2]!["appliedValue"] = "single_datagram";
                    row["axisRecords"]![2]!["selectionSource"] = "forced";
                    decisions[2]!["forcedValue"] = "single_datagram";
                    decisions[2]!["selectedValue"] = "single_datagram";
                    decisions[2]!["appliedValue"] = "single_datagram";
                    break;
                case "safety_source":
                    row["axisRecords"]![1]!["safetyOverride"]!["applied"] = true;
                    row["axisRecords"]![1]!["safetyOverride"]!["reasonCode"] = "recovery_guard";
                    break;
                case "record_kind_key":
                    decisions[2]!["recordKind"] = "packet_plan";
                    decisions[2]!["planKey"] = "wrong-plan";
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(mutation));
            }

            string rowPath = Path.Combine(temporaryDirectory, "row.json");
            string decisionPath = Path.Combine(temporaryDirectory, "decisions.json");
            File.WriteAllText(rowPath, row.ToJsonString());
            File.WriteAllText(decisionPath, decisions.ToJsonString());

            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result =
                AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                    "eng/adaptive-runtime/Test-AdaptiveRuntimeStage1UnifiedEvidence.ps1",
                    "-UnifiedEpochPath",
                    rowPath,
                    "-AxisDecisionPath",
                    decisionPath);

            Assert.NotEqual(0, result.ExitCode);
            using JsonDocument summary = JsonDocument.Parse(result.Output);
            Assert.Contains(
                summary.RootElement.GetProperty("failures")
                    .EnumerateArray()
                    .Select(static failure => failure.GetString()!),
                failure => failure.Contains(expectedFailure, StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(temporaryDirectory, recursive: true);
        }
    }

    private static QuicAdaptiveRuntimeStage1PolicySnapshot CreateSnapshot(
        QuicAdaptiveRuntimeStage1Axis forcedAxis,
        QuicAdaptiveRuntimeStage1PolicyValue forcedValue)
        => new(
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget
                    ? forcedValue
                    : null),
            CreateDecision(
                QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum,
                forcedAxis == QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum
                    ? forcedValue
                    : null));

    private static QuicAdaptiveRuntimeStage1AxisDecision CreateDecision(
        QuicAdaptiveRuntimeStage1Axis axis,
        QuicAdaptiveRuntimeStage1PolicyValue? forcedValue = null,
        bool shadow = false)
    {
        (QuicAdaptiveRuntimeStage1DecisionBoundary boundary,
            QuicAdaptiveRuntimeStage1LatchLifetime lifetime) = axis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.PacketPlan,
                    QuicAdaptiveRuntimeStage1LatchLifetime.PacketPlan),
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.ActorTurn,
                    QuicAdaptiveRuntimeStage1LatchLifetime.ActorTurn),
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                (QuicAdaptiveRuntimeStage1DecisionBoundary.LogicalWriteAdmission,
                    QuicAdaptiveRuntimeStage1LatchLifetime.LogicalWrite),
            _ => throw new ArgumentOutOfRangeException(nameof(axis)),
        };

        QuicAdaptiveRuntimeStage1PolicyValue conservativeValue = axis switch
        {
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendTurnPlanning =>
                QuicAdaptiveRuntimeStage1PolicyValue.Conservative,
            QuicAdaptiveRuntimeStage1Axis.ApplicationSendBatchFormation =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleEligible,
            QuicAdaptiveRuntimeStage1Axis.QueuedSendBurstBudget =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleDatagram,
            QuicAdaptiveRuntimeStage1Axis.OversizedWriteAdmissionQuantum =>
                QuicAdaptiveRuntimeStage1PolicyValue.SingleFragment,
            _ => throw new ArgumentOutOfRangeException(nameof(axis)),
        };
        QuicAdaptiveRuntimeStage1PolicyValue selectedValue =
            forcedValue ?? (shadow
                ? conservativeValue
                : QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent);

        return new QuicAdaptiveRuntimeStage1AxisDecision(
            axis,
            ObservationContractVersion: $"{axis}-observation-v1",
            RuleVersion: $"{axis}-rule-v1",
            SnapshotVersion: $"{axis}-snapshot-v1",
            ReasonVersion: $"{axis}-reasons-v1",
            ProvenanceVersion: $"{axis}-provenance-v1",
            QuicAdaptiveRuntimeStage1Validity.None,
            HasForcedValue: forcedValue.HasValue,
            ForcedValue: forcedValue.GetValueOrDefault(),
            HasShadowRecommendation: shadow,
            ShadowRecommendation: conservativeValue,
            SelectedValue: selectedValue,
            AppliedValue: forcedValue ?? QuicAdaptiveRuntimeStage1PolicyValue.LegacyCurrent,
            SelectionSource: forcedValue.HasValue
                ? QuicAdaptiveRuntimeStage1SelectionSource.Forced
                : shadow
                    ? QuicAdaptiveRuntimeStage1SelectionSource.ShadowRule
                    : QuicAdaptiveRuntimeStage1SelectionSource.LegacySelector,
            ReasonCode: 0,
            QuicAdaptiveRuntimeStage1SafetyOverrideReason.None,
            boundary,
            lifetime,
            QuicAdaptiveRuntimeStage1LatchState.Latched,
            QuicAdaptiveRuntimeStage1FallbackState.NotRequired,
            DecisionSequence: 1,
            LatchSequence: 1);
    }
}
