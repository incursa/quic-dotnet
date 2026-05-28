// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0560">Application protocols that use QUIC SHOULD provide guidance on when deferring an idle timeout is appropriate.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0560")]
public sealed class REQ_QUIC_RFC9000_0560
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ArchitectureArtifact_DescribesWhenApplicationsShouldDeferIdleTimeout()
    {
        using JsonDocument document = LoadArchitectureArtifact();
        JsonElement guidanceSection = GetApplicationIdleTimeoutGuidanceSection(document.RootElement);

        string content = guidanceSection.GetProperty("content").GetString() ?? string.Empty;

        Assert.Contains("Application protocols that use QUIC SHOULD defer the idle timeout only when", content);
        Assert.Contains("explicit, ongoing reason to keep the connection open", content);
        Assert.Contains("REQ-QUIC-RFC9000-S10P1P2-0002", content);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ArchitectureArtifact_DoesNotClaimTransportAutonomyForApplicationPolicy()
    {
        using JsonDocument document = LoadArchitectureArtifact();
        JsonElement guidanceSection = GetApplicationIdleTimeoutGuidanceSection(document.RootElement);

        string content = guidanceSection.GetProperty("content").GetString() ?? string.Empty;

        Assert.DoesNotContain("transport decides application policy", content);
        Assert.DoesNotContain("automatically defer the idle timeout", content);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ArchitectureArtifact_StaysBoundedToDocumentationOwnedGuidance()
    {
        using JsonDocument document = LoadArchitectureArtifact();
        JsonElement guidanceSection = GetApplicationIdleTimeoutGuidanceSection(document.RootElement);

        string content = guidanceSection.GetProperty("content").GetString() ?? string.Empty;

        Assert.Contains("application-owned and documentation-owned", content);
        Assert.Contains("transport helper", content);
    }

    private static JsonDocument LoadArchitectureArtifact()
    {
        string repoRoot = GetRepoRoot();
        string arcPath = Path.Combine(repoRoot, "specs", "architecture", "quic", "ARC-QUIC-RFC9000-0001.json");
        return JsonDocument.Parse(File.ReadAllText(arcPath));
    }

    private static JsonElement GetApplicationIdleTimeoutGuidanceSection(JsonElement root)
    {
        return root.GetProperty("supplemental_sections")
            .EnumerateArray()
            .Single(section => section.GetProperty("heading").GetString() == "Application Idle Timeout Guidance");
    }

    private static string GetRepoRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "src", "Incursa.Quic", "README.md")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root from the test output directory.");
    }
}
