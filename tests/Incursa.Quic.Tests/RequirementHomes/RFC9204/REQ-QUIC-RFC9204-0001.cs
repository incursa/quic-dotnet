// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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
        string qpackBenchmarks = ReadRepositoryFile("benchmarks/QPackPrimitiveBenchmarks.cs");
        string qpackFieldSectionBenchmarks = ReadRepositoryFile("benchmarks/QPackFieldSectionBenchmarks.cs");
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
        Assert.Contains("QPackPrimitiveBenchmarks", qpackBenchmarks, StringComparison.Ordinal);
        Assert.Contains("QPackFieldSectionBenchmarks", qpackFieldSectionBenchmarks, StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QpackMilestoneTestsCoverPrimitivesAndFieldSections()
    {
        string spec = ReadRepositoryFile("specs/requirements/quic/SPEC-QUIC-RFC9204.json");
        string qpackMilestones = ReadRepositoryFile("tests/Incursa.Quic.Tests/QPackMilestoneTests.cs");

        Assert.Contains("PrefixedInteger_RoundTripsBoundaryAndMultibyteValues", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("PrefixedInteger_RejectsTruncatedAndOverflowEncodings", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("StringLiteral_DecodesRawAndHuffmanValues", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("StringLiteral_RejectsTruncatedLengthOrPayload", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("StaticTable_ContainsRfc9204Entries", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("DecodeFieldSection_DecodesRfc9204AppendixB1LiteralWithStaticNameReference", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("DecodeFieldSection_PreservesFieldOrderAndDuplicates", qpackMilestones, StringComparison.Ordinal);
        Assert.Contains("DecodeFieldSection_RejectsTruncatedLiteralFieldLineWithDecompressionFailed", qpackMilestones, StringComparison.Ordinal);
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_QpackPrimitiveEncodingRejectsMalformedBoundariesDeterministically()
    {
        ulong[] values = [0UL, 1UL, 30UL, 31UL, 32UL, 127UL, 128UL, 255UL, 16_383UL, QPackInteger.MaxValue];
        foreach (ulong value in values)
        {
            byte[] encoded = QPackInteger.Encode(value, prefixBitCount: 5);

            ulong decoded = QPackInteger.Decode(encoded, prefixBitCount: 5, out int bytesConsumed);

            Assert.Equal(value, decoded);
            Assert.Equal(encoded.Length, bytesConsumed);
        }

        foreach (byte[] malformed in new[]
        {
            Convert.FromHexString("1F"),
            Convert.FromHexString("1F80808080808080808080"),
            Convert.FromHexString("FFFFFFFFFFFFFFFFFFFFFF7F"),
        })
        {
            QPackException exception = Assert.Throws<QPackException>(
                () => QPackInteger.Decode(malformed, prefixBitCount: 5, out _));

            Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
        }

        Assert.Equal("www.example.com", QPackStringLiteral.Read(
            Convert.FromHexString("8CF1E3C2E5F23A6BA0AB90F4FF"),
            prefixBitCount: 8,
            out int stringBytesConsumed));
        Assert.Equal(13, stringBytesConsumed);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_QpackFieldSectionsRoundTripRepresentativeStaticLiteralAndDuplicateLines()
    {
        QPackFieldLine[][] fieldSections =
        [
            [
                new QPackFieldLine(":method", "GET"),
                new QPackFieldLine(":scheme", "https"),
                new QPackFieldLine(":authority", "example.com"),
                new QPackFieldLine(":path", "/index.html"),
            ],
            [
                new QPackFieldLine(":status", "200"),
                new QPackFieldLine("content-type", "text/plain"),
                new QPackFieldLine("content-length", "5"),
            ],
            [
                new QPackFieldLine("set-cookie", "a=1"),
                new QPackFieldLine("set-cookie", "b=2"),
                new QPackFieldLine("custom-key", "custom-value"),
            ],
        ];

        foreach (QPackFieldLine[] fields in fieldSections)
        {
            byte[] first = QPackEncoder.EncodeFieldSection(fields);
            byte[] second = QPackEncoder.EncodeFieldSection(fields);

            Assert.Equal(first, second);
            Assert.Equal(fields, QPackDecoder.DecodeFieldSection(first));
        }

        QPackException exception = Assert.Throws<QPackException>(
            () => QPackDecoder.DecodeFieldSection(Convert.FromHexString("000027036375")));
        Assert.Equal(QPackErrorCode.DecompressionFailed, exception.ErrorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9204-S6-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_QpackDynamicTableAndInstructionStreamsSynchronizeBlockedSections()
    {
        foreach (int capacity in new[] { 106, 220 })
        {
            QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
            QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

            Assert.True(encoder.TrySetDynamicTableCapacity(capacity, out byte[] capacityInstruction));
            Assert.Empty(decoder.DecodeEncoderStream(capacityInstruction));
            Assert.Equal(capacity, decoder.DynamicTable.Capacity);

            Assert.True(encoder.TryInsert(new QPackFieldLine(":authority", "www.example.com"), out byte[] authorityInstruction));
            Assert.Empty(decoder.DecodeEncoderStream(authorityInstruction));
            Assert.True(decoder.DynamicTable.TryGetByAbsoluteIndex(0, out QPackDynamicTableEntry authority));
            Assert.Equal(new QPackFieldLine(":authority", "www.example.com"), authority.FieldLine);

            QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
                4,
                [
                    new QPackFieldLine(":authority", "www.example.com"),
                ]);
            QPackFieldSectionDecodeResult decoded = decoder.DecodeFieldSection(4, encoded.EncodedFieldSection);

            Assert.False(decoded.IsBlocked);
            Assert.Equal(encoded.RequiredInsertCount, decoded.RequiredInsertCount);
            Assert.Equal([new QPackFieldLine(":authority", "www.example.com")], decoded.FieldLines);

            encoder.DecodeDecoderStream(Convert.FromHexString("84"));
            Assert.Equal(1UL, encoder.KnownReceivedCount);
        }

        QPackDecoder boundedDecoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
        boundedDecoder.DecodeFieldSection(4, Convert.FromHexString("03811011"));
        QPackException blockedLimit = Assert.Throws<QPackException>(
            () => boundedDecoder.DecodeFieldSection(8, Convert.FromHexString("03811011")));
        Assert.Equal(QPackErrorCode.DecompressionFailed, blockedLimit.ErrorCode);
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
            if ((Directory.Exists(gitMarker) || File.Exists(gitMarker)) && File.Exists(specMarker) && File.Exists(testMarker))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to locate the repository root for the RFC 9204 QPACK tests.");
    }
}
