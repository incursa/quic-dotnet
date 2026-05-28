// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Incursa.Quic.Tests;

public sealed class WindowsPathSafetyTests
{
    private const int MaxRelativePathLength = 125;
    private const int MaxProjectedFullPathLength = 240;
    private const string ProjectedCloneRoot = @"C:\src\incursa\.codex-worktrees\quic-dotnet\you-are-one-of-several-parallel-codex-workers-in-00000000-000000-00000000";

    [Fact]
    public void TrackedPathsStayWithinConservativeWindowsCheckoutBudget()
    {
        string[] trackedPaths = GetTrackedPaths();

        PathBudget[] offenders = trackedPaths
            .Select(path => new PathBudget(
                path,
                path.Length,
                Path.Combine(ProjectedCloneRoot, path).Length))
            .Where(path => path.RelativeLength > MaxRelativePathLength ||
                path.ProjectedFullLength > MaxProjectedFullPathLength)
            .OrderByDescending(path => path.RelativeLength)
            .ThenByDescending(path => path.ProjectedFullLength)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "Tracked paths exceed the Windows checkout budget:" + Environment.NewLine +
            string.Join(Environment.NewLine, offenders.Take(20).Select(path =>
                $"{path.RelativeLength}/{path.ProjectedFullLength}: {path.Path}")));
    }

    [Fact]
    public void TrackedBenchmarkEvidenceUsesShortGeneratedArtifactRoots()
    {
        string[] legacyBenchmarkPaths = GetTrackedPaths()
            .Where(path =>
                path.StartsWith("artifacts/benchmark-baseline/", StringComparison.Ordinal) ||
                path.Contains("/BenchmarkDotNet.Artifacts/", StringComparison.Ordinal) ||
                path.EndsWith("/BenchmarkDotNet.Artifacts", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.True(
            legacyBenchmarkPaths.Length == 0,
            "Tracked benchmark evidence must use artifacts/bb and bdn instead of long legacy roots:" +
            Environment.NewLine +
            string.Join(Environment.NewLine, legacyBenchmarkPaths.Take(20)));
    }

    private static string[] GetTrackedPaths()
    {
        string repoRoot = FindRepoRoot();
        ProcessStartInfo startInfo = new("git")
        {
            WorkingDirectory = repoRoot,
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };

        startInfo.ArgumentList.Add("ls-files");

        using Process process = Process.Start(startInfo) ??
            throw new InvalidOperationException("Unable to start git.");

        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        Assert.True(
            process.ExitCode == 0,
            $"git ls-files failed with exit code {process.ExitCode}.{Environment.NewLine}{stderr}");

        return stdout
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Order(StringComparer.Ordinal)
            .ToArray();
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Incursa.Quic.slnx")) &&
                (Directory.Exists(Path.Combine(current.FullName, ".git")) ||
                 File.Exists(Path.Combine(current.FullName, ".git"))))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root.");
    }

    private sealed record PathBudget(string Path, int RelativeLength, int ProjectedFullLength);
}
