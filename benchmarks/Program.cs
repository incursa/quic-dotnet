// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;
using BenchmarkDotNet.Running;

if (args is ["--http3-loopback", ..])
{
    if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS())
    {
        Console.Error.WriteLine("The HTTP/3 loopback harness supports Windows, Linux, and macOS.");
        return 3;
    }

    return await Incursa.Quic.Benchmarks.Http3LoopbackPerformanceHarness.RunAsync(args[1..]);
}

if (args is ["--harness", ..] or ["--leak", ..] or ["--help", ..] or ["--profile", ..] or ["--profile-connect", ..] or ["--profile-runtime", ..] or ["--profile-handshake", ..] or ["--profile-stream", ..] or ["--profile-stream-phases", ..])
{
    ExtractJsonPath(args);
    return Incursa.Quic.Benchmarks.QuicAllocationHarness.Run(
        args.Length > 0 && args[0] is "--harness" or "--leak" or "--help" or "--profile" or "--profile-connect" or "--profile-runtime" or "--profile-handshake" or "--profile-stream" or "--profile-stream-phases" ? args : ["--help"]);
}

BenchmarkSwitcher.FromAssembly(Assembly.GetExecutingAssembly()).Run(UseShortArtifactsRoot(args));
return 0;

static string[] UseShortArtifactsRoot(string[] args)
{
    foreach (string arg in args)
    {
        if (string.Equals(arg, "--artifacts", StringComparison.OrdinalIgnoreCase)
            || arg.StartsWith("--artifacts=", StringComparison.OrdinalIgnoreCase))
        {
            return args;
        }
    }

    string[] updatedArgs = new string[args.Length + 2];
    Array.Copy(args, updatedArgs, args.Length);
    updatedArgs[^2] = "--artifacts";
    updatedArgs[^1] = Path.Combine(Directory.GetCurrentDirectory(), ".artifacts", "bdn");
    return updatedArgs;
}

static void ExtractJsonPath(string[] args)
{
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--json")
        {
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
            {
                Incursa.Quic.Benchmarks.QuicAllocationHarness.JsonOutputPath = args[i + 1];
            }
            else
            {
                Incursa.Quic.Benchmarks.QuicAllocationHarness.JsonOutputPath = string.Empty;
            }
            return;
        }
    }
}
