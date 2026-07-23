// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0170")]
public sealed class REQ_QUIC_CRT_0170
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CatalogFixtureKeepsEveryKnownSeamMeasurementOnly()
    {
        using JsonDocument catalog = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryJson(
            "tests/fixtures/adaptive-runtime-policy/policy-catalog.example.json");
        JsonElement root = catalog.RootElement;

        Assert.Equal("adaptive-runtime-policy-catalog-v1", root.GetProperty("schemaVersion").GetString());
        Assert.True(root.GetProperty("measurementOnly").GetBoolean());
        Assert.True(root.GetProperty("seamLocal").GetBoolean());
        Assert.False(root.GetProperty("activationAuthorized").GetBoolean());

        string[] axisIds = root.GetProperty("scope").GetProperty("axisIds")
            .EnumerateArray()
            .Select(static item => item.GetString()!)
            .ToArray();
        Assert.Contains("receive_credit_publication", axisIds);
        Assert.Contains("oversized_write_admission", axisIds);
        Assert.Contains("application_send_turn_planning", axisIds);
        Assert.Contains("application_datagram_batching", axisIds);
        Assert.Contains("runtime_pressure_advisor", axisIds);

        JsonElement[] entries = root.GetProperty("entries").EnumerateArray().ToArray();
        Assert.All(entries, static entry => Assert.False(entry.GetProperty("activationAuthorized").GetBoolean()));

        JsonElement receiveCredit = entries.Single(static entry =>
            entry.GetProperty("axisId").GetString() == "receive_credit_publication");
        Assert.Equal("executable_measurement", receiveCredit.GetProperty("readiness").GetString());
        Assert.Equal("legacy_current", receiveCredit.GetProperty("runtimeAuthority").GetString());
        Assert.Equal(
            ["forced", "shadow"],
            receiveCredit.GetProperty("measurementModes").EnumerateArray().Select(static item => item.GetString()!).Order().ToArray());

        JsonElement applicationSendTurn = entries.Single(static entry =>
            entry.GetProperty("axisId").GetString() == "application_send_turn_planning");
        Assert.Equal("forceable_campaign_seam", applicationSendTurn.GetProperty("readiness").GetString());
        Assert.True(applicationSendTurn.GetProperty("forceableForCampaigns").GetBoolean());
        Assert.False(applicationSendTurn.GetProperty("shadowSupported").GetBoolean());
        Assert.Equal(
            ["conservative", "legacy_current"],
            applicationSendTurn.GetProperty("policyValues").EnumerateArray().Select(static item => item.GetString()!).Order().ToArray());

        JsonElement advisor = entries.Single(static entry =>
            entry.GetProperty("axisId").GetString() == "runtime_pressure_advisor");
        Assert.Equal("observation_only", advisor.GetProperty("readiness").GetString());
        Assert.False(advisor.GetProperty("forceableForCampaigns").GetBoolean());
        Assert.False(advisor.GetProperty("shadowSupported").GetBoolean());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void CatalogWriterRetainsBlockedActivationCapabilities()
    {
        string writer = AdaptiveRuntimePolicyFixtureTestSupport.ReadRepositoryText(
            "eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1");

        Assert.Contains("active_internal", writer, StringComparison.Ordinal);
        Assert.Contains("online_learning", writer, StringComparison.Ordinal);
        Assert.Contains("production_activation", writer, StringComparison.Ordinal);
        Assert.Contains("axis_widening", writer, StringComparison.Ordinal);
        Assert.Contains("Only receive-credit publication is executable", writer, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CatalogWriterEmitsSchemaValidatedMeasurementOnlyMetadata()
    {
        string repoRoot = AdaptiveRuntimePolicyScriptTestSupport.FindRepoRoot();
        string outputRoot = Path.Combine(repoRoot, ".artifacts", "adaptive-runtime", $"catalog-test-{Guid.NewGuid():N}");
        string outputPath = Path.Combine(outputRoot, "policy-catalog.json");

        try
        {
            AdaptiveRuntimePolicyScriptTestSupport.ProcessResult result = AdaptiveRuntimePolicyScriptTestSupport.RunPowerShellFile(
                "eng/adaptive-runtime/New-AdaptiveRuntimePolicyCatalog.ps1",
                "-OutputPath", outputPath);

            Assert.Equal(0, result.ExitCode);
            Assert.True(File.Exists(outputPath));
            using JsonDocument catalog = JsonDocument.Parse(File.ReadAllText(outputPath));
            JsonElement root = catalog.RootElement;
            Assert.True(root.GetProperty("measurementOnly").GetBoolean());
            Assert.False(root.GetProperty("activationAuthorized").GetBoolean());
            Assert.Single(
                root.GetProperty("entries").EnumerateArray(),
                static entry => entry.GetProperty("readiness").GetString() == "executable_measurement");
        }
        finally
        {
            if (Directory.Exists(outputRoot))
            {
                Directory.Delete(outputRoot, recursive: true);
            }
        }
    }
}
