// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Xunit;

namespace Incursa.Quic.Tests;

public sealed class PrivateReflectionGuardTests
{
    private static readonly string[] AllowlistedFiles =
    [
        "RequirementHomes/CRT/REQ-QUIC-CRT-0051.cs",
        "RequirementHomes/CRT/REQ-QUIC-CRT-0095.cs",
        "RequirementHomes/CRT/REQ-QUIC-CRT-0096.cs",
    ];

    [Fact]
    public void TestsDoNotUsePrivateReflectionOutsideTheQuarantine()
    {
        string testsRoot = GetTestsRoot();
        List<string> offenders = [];

        foreach (string filePath in Directory.EnumerateFiles(testsRoot, "*.cs", SearchOption.AllDirectories))
        {
            if (IsGeneratedOrAllowlisted(filePath, testsRoot))
            {
                continue;
            }

            string source = File.ReadAllText(filePath);
            string nonPublicToken = string.Concat("BindingFlags.", "NonPublic");
            string reflectionNonPublicToken = string.Concat("System.Reflection.BindingFlags.", "NonPublic");
            if (source.Contains(nonPublicToken, StringComparison.Ordinal)
                || source.Contains(reflectionNonPublicToken, StringComparison.Ordinal))
            {
                offenders.Add(Path.GetRelativePath(testsRoot, filePath));
            }
        }

        Assert.True(
            offenders.Count == 0,
            "Private reflection remains outside the quarantine: " + string.Join(", ", offenders));
    }

    private static bool IsGeneratedOrAllowlisted(string filePath, string testsRoot)
    {
        if (Path.GetFileName(filePath).Equals("PrivateReflectionGuardTests.cs", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (filePath.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase)
            || filePath.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        string relativePath = NormalizePath(Path.GetRelativePath(testsRoot, filePath));

        return AllowlistedFiles.Contains(relativePath, StringComparer.OrdinalIgnoreCase);
    }

    private static string NormalizePath(string path) => path.Replace('\\', '/');
    private static string GetTestsRoot()
    {
        string baseDirectory = AppContext.BaseDirectory;
        string repoRoot = Path.GetFullPath(Path.Combine(baseDirectory, "..", "..", "..", "..", ".."));
        return Path.Combine(repoRoot, "tests", "Incursa.Quic.Tests");
    }
}
