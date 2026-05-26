namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9204-S2-0001")]
[Requirement("REQ-QUIC-RFC9204-S5-0001")]
[Requirement("REQ-QUIC-RFC9204-S6-0001")]
public sealed class REQ_QUIC_RFC9204_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QpackCoreTestsAreTraceLinked()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9204.json");
        string architecture = ReadRepositoryFile("specs/architecture/quic/ARC-QUIC-RFC9204-0001.json");
        string workItem = ReadRepositoryFile("specs/work-items/quic/WI-QUIC-RFC9204-0001.json");
        string verification = ReadRepositoryFile("specs/verification/quic/VER-QUIC-RFC9204-0001.json");
        string qpackMilestones = ReadRepositoryFile("tests/Incursa.Quic.Tests/QPackMilestoneTests.cs");
        string qpackInstructions = ReadRepositoryFile("tests/Incursa.Quic.Tests/QPackInstructionStreamTests.cs");
        string qpackMatrix = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3QPackErrorHandlingMatrixTests.cs");
        string qpackReadme = ReadRepositoryFile("src/Incursa.Qpack/README.md");

        Assert.Contains("REQ-QUIC-RFC9204-S2-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S5-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S6-0001", spec, StringComparison.Ordinal);
        Assert.Contains("ARC-QUIC-RFC9204-0001", spec, StringComparison.Ordinal);
        Assert.Contains("WI-QUIC-RFC9204-0001", spec, StringComparison.Ordinal);
        Assert.Contains("VER-QUIC-RFC9204-0001", spec, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S2-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S5-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S6-0001", architecture, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S2-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S5-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S6-0001", workItem, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S2-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S5-0001", verification, StringComparison.Ordinal);
        Assert.Contains("REQ-QUIC-RFC9204-S6-0001", verification, StringComparison.Ordinal);
        Assert.Contains("Incursa.Qpack", qpackReadme, StringComparison.Ordinal);
        Assert.Contains("deterministic", qpackReadme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("QPackMilestoneTests", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("QPackInstructionStreamTests", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("Http3QPackErrorHandlingMatrixTests", qpackMatrix, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QpackMilestoneTestsCoverPrimitivesAndFieldSections()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9204.json");
        string qpackMilestones = ReadRepositoryFile("tests/Incursa.Quic.Tests/QPackMilestoneTests.cs");

        Assert.Contains("PrefixedInteger_RoundTripsBoundaryAndMultibyteValues", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("StaticTable_ContainsRfc9204Entries", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("DecodeFieldSection_DecodesRfc9204AppendixB1LiteralWithStaticNameReference", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("DecodeFieldSection_PreservesFieldOrderAndDuplicates", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("EncodeFieldSection_IsDeterministicForCommonHttp3Request", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("EncodeFieldSection_RoundTripsCommonHttp3Response", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("QPACK", spec, StringComparison.Ordinal);
        Assert.Contains("field-section encoding and decoding", spec, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QpackInstructionStreamTestsCoverDynamicStateAndMalformedInput()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9204.json");
        string qpackInstructions = ReadRepositoryFile("tests/Incursa.Quic.Tests/QPackInstructionStreamTests.cs");
        string qpackMatrix = ReadRepositoryFile("tests/Incursa.Quic.Tests/Http3QPackErrorHandlingMatrixTests.cs");

        Assert.Contains("EncoderStreamParser_ParsesSetDynamicTableCapacityAcrossPartialBuffers", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("EncoderStreamParser_ParsesInsertWithStaticNameReference", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("EncoderStreamParser_ParsesInsertWithDynamicNameReference", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("EncoderStreamParser_ParsesInsertWithLiteralNameAcrossPartialBuffers", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("EncoderStreamParser_ParsesDuplicate", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("DecoderStreamParser_ParsesSectionAcknowledgmentAcrossPartialBuffers", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("DecoderStreamParser_ParsesStreamCancellation", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("DecoderStreamParser_ParsesInsertCountIncrement", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("InstructionStreams_SynchronizeEncoderAndDecoderDynamicState", qpackInstructions, StringComparison.Ordinal);
        Assert.Contains("QPackFieldSection_InvalidDynamicReference_ThrowsDecompressionFailed", qpackMatrix, StringComparison.Ordinal);
        Assert.Contains("QPackEncoderStream_DynamicNameReferenceToEvictedEntry_ThrowsEncoderStreamError", qpackMatrix, StringComparison.Ordinal);
        Assert.Contains("QPACK module MUST track dynamic table capacity", spec, StringComparison.Ordinal);
        Assert.Contains("encoder/decoder instruction-stream parsing", spec, StringComparison.OrdinalIgnoreCase);
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
            string specMarker = Path.Combine(current.FullName, "specs", "requirements", "quic", "SPEC-QUIC-RFC9204.json");
            string testMarker = Path.Combine(current.FullName, "tests", "Incursa.Quic.Tests", "QPackMilestoneTests.cs");
            if (Directory.Exists(gitMarker) && File.Exists(specMarker) && File.Exists(testMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9204 QPACK tests.");
    }
}
