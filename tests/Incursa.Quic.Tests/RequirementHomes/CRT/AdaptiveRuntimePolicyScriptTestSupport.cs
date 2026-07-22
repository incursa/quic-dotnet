// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Text.Json;

namespace Incursa.Quic.Tests;

internal static class AdaptiveRuntimePolicyScriptTestSupport
{
    public static JsonDocument ReadRepositoryJson(string relativePath)
        => JsonDocument.Parse(File.ReadAllText(FindRepositoryFile(relativePath)));

    public static string FindRepositoryFile(string relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            string candidate = Path.Combine(directory.FullName, relativePath.Replace('/', Path.DirectorySeparatorChar));
            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException($"Unable to locate repository file '{relativePath}'.");
    }

    public static string FindRepoRoot()
    {
        string supportFile = FindRepositoryFile(
            "tests/Incursa.Quic.Tests/RequirementHomes/CRT/AdaptiveRuntimePolicyScriptTestSupport.cs");
        DirectoryInfo? directory = new(Path.GetDirectoryName(supportFile)!);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Directory.Build.props")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("Unable to locate the repository root from the adaptive-runtime test support file.");
    }

    public static ProcessResult RunPowerShellFile(string scriptRelativePath, params string[] arguments)
    {
        string scriptPath = FindRepositoryFile(scriptRelativePath);
        return RunPowerShell(["-File", scriptPath, .. arguments]);
    }

    public static ProcessResult RunPowerShellCommand(string command)
        => RunPowerShell(["-Command", command]);

    public static string QuotePowerShellLiteral(string value)
        => $"'{value.Replace("'", "''", StringComparison.Ordinal)}'";

    private static ProcessResult RunPowerShell(string[] arguments)
    {
        string powerShellExecutable = ResolvePowerShellExecutable();
        var startInfo = new ProcessStartInfo(powerShellExecutable)
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
        };

        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Failed to start PowerShell.");
        string output = process.StandardOutput.ReadToEnd();
        string error = process.StandardError.ReadToEnd();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("PowerShell script did not exit within 30 seconds.");
        }

        return new ProcessResult(process.ExitCode, output + error);
    }

    private static string ResolvePowerShellExecutable()
    {
        string[] candidates = OperatingSystem.IsWindows()
            ? ["pwsh.exe", "pwsh", "powershell.exe", "powershell"]
            : ["pwsh", "pwsh.exe"];

        foreach (string candidate in candidates)
        {
            string? resolved = ResolveExecutableOnPath(candidate);
            if (resolved is not null)
            {
                return resolved;
            }
        }

        throw new InvalidOperationException("Unable to locate a PowerShell executable on PATH.");
    }

    private static string? ResolveExecutableOnPath(string fileName)
    {
        if (Path.IsPathRooted(fileName) && File.Exists(fileName))
        {
            return fileName;
        }

        string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string candidate = Path.Combine(directory, fileName);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    internal readonly record struct ProcessResult(int ExitCode, string Output);
}
