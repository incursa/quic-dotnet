using System.Reflection;
using BenchmarkDotNet.Running;

BenchmarkSwitcher.FromAssembly(Assembly.GetExecutingAssembly()).Run(UseShortArtifactsRoot(args));

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
