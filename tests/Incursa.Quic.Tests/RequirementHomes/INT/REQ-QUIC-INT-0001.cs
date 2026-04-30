using System.Xml.Linq;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0001")]
public sealed class REQ_QUIC_INT_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void InteropEndpointLivesInACompanionExecutableProjectThatReferencesTheLibrary()
    {
        string repoRoot = FindRepoRoot();
        XDocument harnessProject = XDocument.Load(Path.Combine(
            repoRoot,
            "src",
            "Incursa.Quic.InteropHarness",
            "Incursa.Quic.InteropHarness.csproj"));
        XDocument solution = XDocument.Load(Path.Combine(repoRoot, "Incursa.Quic.slnx"));

        Assert.Equal("Microsoft.NET.Sdk", harnessProject.Root?.Attribute("Sdk")?.Value);
        Assert.Equal("Exe", GetPropertyValue(harnessProject, "OutputType"));
        Assert.Equal("false", GetPropertyValue(harnessProject, "IsPackable"));
        Assert.Equal("Incursa.Quic.InteropHarness", GetPropertyValue(harnessProject, "AssemblyName"));
        Assert.Equal("Incursa.Quic.InteropHarness", GetPropertyValue(harnessProject, "RootNamespace"));

        string[] projectReferences = GetProjectReferences(harnessProject);
        Assert.Contains("../Incursa.Quic/Incursa.Quic.csproj", projectReferences);
        Assert.DoesNotContain("../../tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj", projectReferences);

        string[] solutionProjects = solution
            .Descendants("Project")
            .Select(element => NormalizePath(element.Attribute("Path")?.Value ?? string.Empty))
            .ToArray();

        Assert.Contains("src/Incursa.Quic/Incursa.Quic.csproj", solutionProjects);
        Assert.Contains("src/Incursa.Quic.InteropHarness/Incursa.Quic.InteropHarness.csproj", solutionProjects);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MainLibraryProjectDoesNotBecomeTheInteropEndpointApplication()
    {
        string repoRoot = FindRepoRoot();
        XDocument libraryProject = XDocument.Load(Path.Combine(
            repoRoot,
            "src",
            "Incursa.Quic",
            "Incursa.Quic.csproj"));

        Assert.NotEqual("Exe", GetPropertyValue(libraryProject, "OutputType"));
        Assert.Equal("true", GetPropertyValue(libraryProject, "IsPackable"));
        Assert.DoesNotContain(
            "../Incursa.Quic.InteropHarness/Incursa.Quic.InteropHarness.csproj",
            GetProjectReferences(libraryProject));
    }

    private static string? GetPropertyValue(XDocument project, string propertyName)
        => project.Descendants(propertyName).Select(element => element.Value).FirstOrDefault();

    private static string[] GetProjectReferences(XDocument project)
        => project.Descendants("ProjectReference")
            .Select(element => NormalizePath(element.Attribute("Include")?.Value ?? string.Empty))
            .Where(value => value.Length > 0)
            .ToArray();

    private static string NormalizePath(string path)
        => path.Replace('\\', '/');

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string candidate = Path.Combine(current.FullName, "Incursa.Quic.slnx");
            if (File.Exists(candidate))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for INT-0001 project-shape proof.");
    }
}
