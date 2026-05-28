// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class InteropHarnessKeylogHonestyTests
{
    [Theory]
    [InlineData("client")]
    [InlineData("server")]
    public void RunHonorsSslKeyLogFileWithoutPretendingToSupportKeylogExport(string role)
    {
        using TempDirectoryFixture fixture = new(nameof(InteropHarnessKeylogHonestyTests));
        string qlogDirectory = fixture.CreateSubdirectory("qlog");
        string keyLogPath = Path.Combine(fixture.RootDirectory, $"{role}-keys.log");
        IDictionary environment = InteropHarnessTestSupport.CreateEnvironment(
            role,
            "multipath",
            qlogDir: qlogDirectory,
            sslKeyLogFile: keyLogPath);

        using StringWriter stdout = new();
        using StringWriter stderr = new();

        int exitCode = InteropHarnessRunner.Run(environment, stdout, stderr);

        Assert.Equal(127, exitCode);
        Assert.Equal(
            $"interop harness: role={role}, testcase=multipath, SSLKEYLOGFILE is set but this unsupported testcase does not execute keylog export.{Environment.NewLine}" +
            $"interop harness: role={role}, testcase=multipath, requestCount=0 is currently unsupported.{Environment.NewLine}",
            stdout.ToString());
        Assert.Equal(string.Empty, stderr.ToString());
        Assert.False(File.Exists(keyLogPath));
        Assert.Empty(Directory.GetFiles(qlogDirectory, "*.qlog"));
    }
}
