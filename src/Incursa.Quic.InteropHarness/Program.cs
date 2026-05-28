// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.InteropHarness;

internal static class Program
{
    internal static int Main(string[] args)
    {
        _ = args;
        return InteropHarnessRunner.Run(Environment.GetEnvironmentVariables(), Console.Out, Console.Error);
    }
}
