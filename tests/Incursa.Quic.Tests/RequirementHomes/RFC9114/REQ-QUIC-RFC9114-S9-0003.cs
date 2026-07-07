// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9114_S9_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9114-S9-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_DynamicQpackStateFeedsHttp3HeadersFramesDeterministically()
    {
        foreach (int capacity in new[] { 106, 220 })
        {
            QPackEncoder encoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);
            QPackDecoder decoder = new(maximumDynamicTableCapacity: 220, maximumBlockedStreams: 1);

            Assert.True(encoder.TrySetDynamicTableCapacity(capacity, out byte[] capacityInstruction));
            Assert.True(encoder.TryInsert(new QPackFieldLine("server", "incursa-dynamic"), out byte[] serverInstruction));
            QPackFieldSectionEncodeResult encoded = encoder.EncodeFieldSection(
                0,
                [
                    new QPackFieldLine(":status", "200"),
                    new QPackFieldLine("server", "incursa-dynamic"),
                    new QPackFieldLine("content-length", "0"),
                ]);
            Assert.True(encoded.RequiredInsertCount > 0);

            Http3HeadersFrame headersFrame = Assert.IsType<Http3HeadersFrame>(
                ReadFrame(Http3FrameWriter.WriteHeaders(encoded.EncodedFieldSection)));
            QPackFieldSectionDecodeResult blocked = decoder.DecodeFieldSection(0, headersFrame.EncodedFieldSection);
            Assert.True(blocked.IsBlocked);

            Assert.Empty(decoder.DecodeEncoderStream(capacityInstruction));
            QPackFieldSectionDecodeResult decoded = Assert.Single(decoder.DecodeEncoderStream(serverInstruction));

            Assert.False(decoded.IsBlocked);
            Assert.Equal(
                [
                    new QPackFieldLine(":status", "200"),
                    new QPackFieldLine("server", "incursa-dynamic"),
                    new QPackFieldLine("content-length", "0"),
                ],
                decoded.FieldLines);
        }
    }

    private static Http3Frame ReadFrame(byte[] encoded)
    {
        return Assert.Single(new Http3FrameReader().Read(encoded));
    }
}
