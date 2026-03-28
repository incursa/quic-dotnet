using System.Reflection;

namespace Incursa.Quic.Tests;

/// <summary>
/// Scaffold-level tests that verify the repository wiring stays intact.
/// </summary>
public sealed class ScaffoldTests
{
    /// <summary>
    /// Ensures the library assembly can be loaded by the test project.
    /// </summary>
    [Fact]
    [Trait("Category", "Smoke")]
    public void LibraryAssemblyCanBeLoaded()
    {
        Assembly assembly = Assembly.Load("Incursa.Quic");

        Assert.Equal("Incursa.Quic", assembly.GetName().Name);
    }

    /// <summary>
    /// Ensures the package-relevant baseline files are present in the library project.
    /// </summary>
    [Fact]
    [Trait("Category", "Blocking")]
    public void PublicApiBaselineFilesExist()
    {
        string repoRoot = GetRepoRoot();
        string projectDirectory = Path.Combine(repoRoot, "src", "Incursa.Quic");

        Assert.True(File.Exists(Path.Combine(projectDirectory, "PublicAPI.Shipped.txt")));
        Assert.True(File.Exists(Path.Combine(projectDirectory, "PublicAPI.Unshipped.txt")));
        Assert.True(File.Exists(Path.Combine(projectDirectory, "README.md")));
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
}
