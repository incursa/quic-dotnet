// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

[Collection(QuicLoopbackNetworkTestCollection.Name)]
[Requirement("REQ-QUIC-INT-0024")]
public sealed class REQ_QUIC_INT_0024
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MsquicMajorPeerFailuresStayClassifiedAsPeerSideBlockedEvidence()
    {
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string gapLedger = ReadRepositoryFile("specs/requirements/quic/REQUIREMENT-GAPS.md");
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-INT.json");
        string reportJson = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-evidence-25904716076.json");
        string reportMarkdown = ReadRepositoryFile("specs/generated/quic/interop-major-peer-matrix-evidence-25904716076.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0018.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0018.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0018.json");

        Assert.Contains("REQ-QUIC-INT-0024", spec, StringComparison.Ordinal);
        Assert.Contains("msquic major-peer failures", spec, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("peer-tls-alert-50", spec, StringComparison.Ordinal);
        Assert.Contains("peer-connection-terminated", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-INT-0024", currentStatus, StringComparison.Ordinal);
        Assert.Contains("peer-side blocked evidence", currentStatus, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("interop-msquic-peer-blocked-evidence", gapLedger, StringComparison.Ordinal);
        Assert.Contains("msquic Peer-Blocked Evidence Classification Architecture", architecture, StringComparison.Ordinal);
        Assert.Contains("peer-side blocked evidence", architecture, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("WI-QUIC-INT-0018", architecture, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-INT-0018", architecture, StringComparison.Ordinal);
        Assert.Contains("msquic peer-side blocked evidence", workItem, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("REQ-QUIC-INT-0024", verification, StringComparison.Ordinal);
        Assert.Contains("\"status\": \"complete\"", workItem, StringComparison.Ordinal);
        Assert.Contains("\"status\": \"passed\"", verification, StringComparison.Ordinal);

        using JsonDocument reportDocument = JsonDocument.Parse(reportJson);
        JsonElement root = reportDocument.RootElement;
        Assert.Equal("interop-major-peer-matrix-evidence-25904716076", root.GetProperty("report_id").GetString());
        Assert.Equal(11, root.GetProperty("outcome_counts").GetProperty("passed").GetInt32());
        Assert.Equal(9, root.GetProperty("outcome_counts").GetProperty("failed").GetInt32());
        JsonElement failureClassCounts = root.GetProperty("failure_class_counts");
        Assert.Equal(5, failureClassCounts.GetProperty("peer-tls-alert-50").GetInt32());
        Assert.Equal(1, failureClassCounts.GetProperty("peer-connection-terminated").GetInt32());
        Assert.Contains("| client-handshake-msquic | msquic | client | handshake | 0 | failed | peer-tls-alert-50 |", reportMarkdown, StringComparison.Ordinal);
        Assert.Contains("| server-resumption-msquic | msquic | server | resumption | 180 | failed | peer-connection-terminated |", reportMarkdown, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MsquicMajorPeerFailuresDoNotReplaceTheQuicGoLocalCandidate()
    {
        string currentStatus = ReadRepositoryFile("docs/current-status.md");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-INT-0018.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-INT-0018.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-INT-0018.json");

        string msquicSection = ExtractSection(
            currentStatus,
            "## 2026-05-16 INT Msquic Peer-Blocked Evidence Lane",
            "## 2026-05-14 RFC9000 S19P21 and S5 Trace Closure");

        Assert.Contains("peer-side blocked evidence", msquicSection, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("QuicConnectionRuntime", msquicSection, StringComparison.Ordinal);
        Assert.DoesNotContain("KeepAliveInterval", msquicSection, StringComparison.Ordinal);
        Assert.DoesNotContain("QuicConnectionRuntime", architecture, StringComparison.Ordinal);
        Assert.DoesNotContain("KeepAliveInterval", architecture, StringComparison.Ordinal);
        Assert.DoesNotContain("QuicConnectionRuntime", workItem, StringComparison.Ordinal);
        Assert.DoesNotContain("KeepAliveInterval", workItem, StringComparison.Ordinal);
        Assert.DoesNotContain("QuicConnectionRuntime", verification, StringComparison.Ordinal);
        Assert.DoesNotContain("KeepAliveInterval", verification, StringComparison.Ordinal);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-INT.json");
            string helperMarker = Path.Combine(current.FullName, "scripts", "interop", "Invoke-QuicInteropRunner.ps1");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(helperMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the msquic peer-blocked evidence requirement home test.");
    }

    private static string ExtractSection(
        string text,
        string startMarker,
        string endMarker)
    {
        int startIndex = text.IndexOf(startMarker, StringComparison.Ordinal);
        Assert.True(startIndex >= 0, $"Unable to find section start marker '{startMarker}'.");

        int endIndex = text.IndexOf(endMarker, startIndex + startMarker.Length, StringComparison.Ordinal);
        Assert.True(endIndex > startIndex, $"Unable to find section end marker '{endMarker}'.");

        return text[startIndex..endIndex];
    }
}
