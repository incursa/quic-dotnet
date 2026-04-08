namespace Incursa.Quic.InteropHarness;

internal static class Program
{
    internal static int Main(string[] args)
    {
        _ = args;
        return InteropHarnessRunner.Run(Environment.GetEnvironmentVariables(), Console.Out, Console.Error);
    }
}
