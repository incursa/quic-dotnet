// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace Incursa.Quic.Tests;

internal static class QuicRfc9001TailProofTestSupport
{
    internal static void AssertCanonicalArtifactsOwnRequirement(
        string requirementId,
        params string[] expectedKeyComponents)
    {
        using JsonDocument spec = ReadJson("specs/requirements/quic/SPEC-QUIC-RFC9001.json");
        JsonElement requirement = spec.RootElement
            .GetProperty("requirements")
            .EnumerateArray()
            .Single(entry => entry.GetProperty("id").GetString() == requirementId);

        JsonElement trace = requirement.GetProperty("trace");
        string architectureId = GetFirstString(trace.GetProperty("satisfied_by"));
        string workItemId = GetFirstString(trace.GetProperty("implemented_by"));
        string verificationId = GetFirstString(trace.GetProperty("verified_by"));

        using JsonDocument architecture = ReadJson($"specs/architecture/quic/{architectureId}.json");
        Assert.Equal(architectureId, architecture.RootElement.GetProperty("artifact_id").GetString());
        Assert.Equal("implemented", architecture.RootElement.GetProperty("status").GetString());
        AssertJsonArrayContains(architecture.RootElement.GetProperty("satisfies"), requirementId);
        foreach (string expectedKeyComponent in expectedKeyComponents)
        {
            AssertJsonArrayContains(architecture.RootElement.GetProperty("key_components"), expectedKeyComponent);
        }

        using JsonDocument workItem = ReadJson($"specs/work-items/quic/{workItemId}.json");
        Assert.Equal(workItemId, workItem.RootElement.GetProperty("artifact_id").GetString());
        Assert.Equal("complete", workItem.RootElement.GetProperty("status").GetString());
        AssertJsonArrayContains(workItem.RootElement.GetProperty("addresses"), requirementId);

        using JsonDocument verification = ReadJson($"specs/verification/quic/{verificationId}.json");
        Assert.Equal(verificationId, verification.RootElement.GetProperty("artifact_id").GetString());
        Assert.Equal("passed", verification.RootElement.GetProperty("status").GetString());
        AssertJsonArrayContains(verification.RootElement.GetProperty("verifies"), requirementId);
    }

    internal static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }

    internal static byte[] BuildMinimalInitialPacket()
    {
        return
        [
            0xC0,
            0x00, 0x00, 0x00, 0x01,
            0x00,
            0x00,
            0x00,
            0x01,
            0x00,
        ];
    }

    internal static byte[] BuildMinimalHandshakePacket()
    {
        return
        [
            0xE0,
            0x00, 0x00, 0x00, 0x01,
            0x00,
            0x00,
            0x01,
            0x00,
        ];
    }

    internal static byte[] BuildMinimalOneRttPacket()
    {
        return [0x40];
    }

    private static JsonDocument ReadJson(string repoRelativePath)
    {
        return JsonDocument.Parse(File.ReadAllText(GetRepoPath(repoRelativePath)));
    }

    private static string GetRepoPath(string repoRelativePath)
    {
        return Path.Combine(GetRepoRoot(), repoRelativePath.Replace('/', Path.DirectorySeparatorChar));
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

    private static void AssertJsonArrayContains(JsonElement array, string expected)
    {
        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        Assert.Contains(array.EnumerateArray(), element => element.GetString() == expected);
    }

    private static string GetFirstString(JsonElement array)
    {
        Assert.Equal(JsonValueKind.Array, array.ValueKind);
        JsonElement first = array.EnumerateArray().First();
        string? value = first.GetString();
        Assert.False(string.IsNullOrWhiteSpace(value));
        return value;
    }
}
