// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S22P1P4-0005">Any stricter requirements for permanent registrations MUST NOT prevent provisional registrations for affected codepoints.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S22P1P4-0005")]
public sealed class REQ_QUIC_RFC9000_S22P1P4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RequirementStatement_PreventsPermanentRequirementsFromBlockingProvisionalRegistrations()
    {
        string repoRoot = GetRepoRoot();
        string specPath = Path.Combine(repoRoot, "specs", "requirements", "quic", "SPEC-QUIC-RFC9000.json");

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(specPath));
        JsonElement requirement = document.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == "REQ-QUIC-RFC9000-S22P1P4-0005");

        Assert.Equal("Do not block provisional registrations with stricter permanent requirements", requirement.GetProperty("title").GetString());
        Assert.Equal("Any stricter requirements for permanent registrations MUST NOT prevent provisional registrations for affected codepoints.", requirement.GetProperty("statement").GetString());
        Assert.Equal("RFC 9000 §22.1.4 RFC9000-S22.1.4-B4-P3-S1", requirement.GetProperty("trace").GetProperty("upstream_refs")[0].GetString());
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
