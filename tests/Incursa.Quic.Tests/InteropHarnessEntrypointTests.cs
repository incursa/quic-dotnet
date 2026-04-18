using System.IO;

namespace Incursa.Quic.Tests;

[CollectionDefinition(nameof(InteropHarnessEntrypointTestsCollection), DisableParallelization = true)]
public sealed class InteropHarnessEntrypointTestsCollection
{
}

[Collection(nameof(InteropHarnessEntrypointTestsCollection))]
public sealed class InteropHarnessEntrypointTests
{
    [Fact]
    public void MainUsesProcessEnvironmentAndIgnoresCommandLineArguments()
    {
        string? originalRole = Environment.GetEnvironmentVariable("ROLE");
        string? originalTestcase = Environment.GetEnvironmentVariable("TESTCASE");
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        StringWriter stdout = new();
        StringWriter stderr = new();

        try
        {
            Environment.SetEnvironmentVariable("ROLE", "client");
            Environment.SetEnvironmentVariable("TESTCASE", "multipath");

            Console.SetOut(stdout);
            Console.SetError(stderr);

            int exitCode = Program.Main(["server", "handshake"]);

            Assert.Equal(127, exitCode);
            Assert.Equal(
                $"interop harness: role=client, testcase=multipath, requestCount=0 is currently unsupported.{Environment.NewLine}",
                stdout.ToString());
            Assert.Equal(string.Empty, stderr.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
            stdout.Dispose();
            stderr.Dispose();
            Environment.SetEnvironmentVariable("ROLE", originalRole);
            Environment.SetEnvironmentVariable("TESTCASE", originalTestcase);
        }
    }
}
