// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Reflection;
using BenchmarkDotNet.Running;

if (args is ["--harness", ..] or ["--leak", ..] or ["--help"])
{
    return Incursa.Quic.Benchmarks.QuicAllocationHarness.Run(args == ["--help"] ? ["--help"] : args);
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
