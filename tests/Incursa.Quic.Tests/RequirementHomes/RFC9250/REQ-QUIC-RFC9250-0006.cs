namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9250-0047")]
public sealed class REQ_QUIC_RFC9250_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqServfailTraceArtifactsAreLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9250.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9250-0006.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9250-0006.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9250-0006.json");

        Assert.Contains("ARC-QUIC-RFC9250-0006", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9250-0006", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9250-0006", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0047", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0047", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9250-0047", verification, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void DoqServfailResponseCodeAndTestsAreTraceLinked()
    {
        string client = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqClient.cs");
        string server = ReadRepositoryFile("src/Incursa.Quic.Dns/DoqServer.cs");
        string tests = ReadRepositoryFile("tests/Incursa.Quic.Tests/DoqStreamLifecycleTests.cs");

        Assert.Contains("ValidateZeroMessageId(response.Payload.Span, \"response\")", client, StringComparison.Ordinal);
        Assert.Contains("DoqStream.WriteMessageAndCompleteAsync(stream, result.Response, cancellationToken)", server, StringComparison.Ordinal);
        Assert.Contains("QueryAsync_PropagatesServfailResponseCodeFromHandler", tests, StringComparison.Ordinal);
        Assert.Contains("CreateDnsServfailResponse", tests, StringComparison.Ordinal);
    }

    private static string ReadRepositoryFile(string relativePath)
    {
        string repoRoot = FindRepoRoot();
        string candidate = Path.Combine(repoRoot, relativePath);
        if (File.Exists(candidate))
        {
            return File.ReadAllText(candidate);
        }

        throw new InvalidOperationException($"Unable to locate '{relativePath}' under '{repoRoot}'.");
    }

    private static string FindRepoRoot()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            string gitMarker = Path.Combine(current.FullName, ".git");
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9250.json");
            string codeMarker = Path.Combine(current.FullName, "src", "Incursa.Quic.Dns", "DoqClient.cs");
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(codeMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9250 DoQ SERVFAIL tests.");
    }
}
