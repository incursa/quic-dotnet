// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_HeaderFormBitIsSet()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            byte[] packet = BuildLongHeaderPacket(testCase);

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_FixedBitIsSetForVersionOneLongHeaders()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.True(header.FixedBit);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_LongPacketTypeFieldIsTwoBits()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.InRange(header.LongPacketTypeBits, (byte)0, (byte)3);
            Assert.Equal((byte)testCase.PacketType, header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_TypeSpecificBitsAreFourBits()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.InRange(header.TypeSpecificBits, (byte)0, (byte)15);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_VersionFieldIsThirtyTwoBitsAndPreserved()
    {
        foreach (uint version in new[] { QuicVersionNegotiation.Version1, QuicVersionNegotiation.Version2, 0xA1A2A3A4U })
        {
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version,
                destinationConnectionId: SequentialBytes(0xD0, 8),
                sourceConnectionId: SequentialBytes(0x50, 4),
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData(
                    token: [],
                    packetNumber: [0x01],
                    protectedPayload: [0xAA]));

            Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
            Assert.Equal(version, header.Version);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_DestinationConnectionIdLengthIsEightBits()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_DestinationConnectionIdIsZeroToTwentyBytesForVersionOne()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.InRange(header.DestinationConnectionId.Length, 0, 20);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0008")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_SourceConnectionIdLengthIsEightBits()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_SourceConnectionIdIsZeroToTwentyBytesForVersionOne()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.InRange(header.SourceConnectionId.Length, 0, 20);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PreOneRttPackets_MapToLongHeaderPacketNumberSpaces()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            byte[] packet = BuildLongHeaderPacket(testCase);

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Long, headerForm);
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
            if (testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.Handshake)
            {
                Assert.NotEqual(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
            }
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ApplicationDataPackets_ClassifyAsShortHeaderPacketNumberSpace()
    {
        foreach (int remainderLength in new[] { 0, 1, 8, 64 })
        {
            byte[] packet = QuicHeaderTestData.BuildShortHeader(
                headerControlBits: (byte)(remainderLength & 0x3F),
                remainder: SequentialBytes(0xA0, remainderLength));

            Assert.True(QuicPacketParser.TryClassifyHeaderForm(packet, out QuicHeaderForm headerForm));
            Assert.Equal(QuicHeaderForm.Short, headerForm);
            Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
            Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_ContainsTheCommonLongHeaderFields()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
            Assert.Equal(testCase.Version, header.Version);
            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
            Assert.False(header.VersionSpecificData.IsEmpty);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_FirstByteMostSignificantBitIsSet()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            byte[] packet = BuildLongHeaderPacket(testCase);

            Assert.Equal(QuicPacketHeaderBits.HeaderFormBitMask, packet[0] & QuicPacketHeaderBits.HeaderFormBitMask);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0014")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_FixedBitIsSetUnlessVersionNegotiation()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.True(header.FixedBit);
        }

        byte[] versionNegotiation = QuicHeaderTestData.BuildVersionNegotiation(
            headerControlBits: 0x00,
            destinationConnectionId: [0xD0],
            sourceConnectionId: [0x50],
            1);
        Assert.True(QuicPacketParser.TryParseVersionNegotiation(
            versionNegotiation,
            out QuicVersionNegotiationPacket versionNegotiationPacket));
        Assert.Equal(0, versionNegotiation[0] & QuicPacketHeaderBits.FixedBitMask);
        Assert.Equal(0U, versionNegotiationPacket.Version);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0015")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionOneLongHeader_WithClearedFixedBitIsRejected()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            byte[] packet = BuildLongHeaderPacket(testCase);
            packet[0] = (byte)(packet[0] & ~QuicPacketHeaderBits.FixedBitMask);

            Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_FirstByteTypeBitsContainPacketType()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            byte[] packet = BuildLongHeaderPacket(testCase);
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(
                (byte)(((packet[0] & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift) & 0x03),
                header.LongPacketTypeBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_VersionDeterminesPacketTypeInterpretation()
    {
        byte[] versionOneRetry = QuicRetryPacketRequirementTestData.BuildRetryPacket(version: QuicVersionNegotiation.Version1);
        byte[] versionTwoRetry = QuicRetryPacketRequirementTestData.BuildRetryPacket(version: QuicVersionNegotiation.Version2);

        Assert.True(QuicPacketParser.TryParseLongHeader(versionOneRetry, out QuicLongHeaderPacket versionOneHeader));
        Assert.True(QuicPacketParser.TryParseLongHeader(versionTwoRetry, out QuicLongHeaderPacket versionTwoHeader));
        Assert.True(QuicVersionNegotiation.IsLongHeaderPacketType(
            versionOneHeader.Version,
            versionOneHeader.LongPacketTypeBits,
            QuicLongPacketType.Retry));
        Assert.True(QuicVersionNegotiation.IsLongHeaderPacketType(
            versionTwoHeader.Version,
            versionTwoHeader.LongPacketTypeBits,
            QuicLongPacketType.Retry));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0019")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_ConnectionIdLengthsAreEncodedAsEightBitUnsignedIntegers()
    {
        foreach (int connectionIdLength in new[] { 0, 1, 20, 255 })
        {
            byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: 0x4E,
                destinationConnectionId: SequentialBytes(0xD0, connectionIdLength),
                sourceConnectionId: SequentialBytes(0x50, connectionIdLength),
                1);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
            Assert.Equal(connectionIdLength, header.DestinationConnectionIdLength);
            Assert.Equal(connectionIdLength, header.SourceConnectionIdLength);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0020")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionOneLongHeader_RejectsConnectionIdsLongerThanTwentyBytes()
    {
        foreach ((int destinationLength, int sourceLength) in new[] { (21, 1), (1, 21), (21, 21), (255, 255) })
        {
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: QuicVersionNegotiation.Version1,
                destinationConnectionId: SequentialBytes(0xD0, destinationLength),
                sourceConnectionId: SequentialBytes(0x50, sourceLength),
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));

            Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionOneLongHeader_DropsConnectionIdLengthValuesLargerThanTwenty()
    {
        foreach (int connectionIdLength in new[] { 21, 32, 160, 255 })
        {
            byte[] packet = QuicHeaderTestData.BuildLongHeader(
                headerControlBits: 0x40,
                version: QuicVersionNegotiation.Version1,
                destinationConnectionId: SequentialBytes(0xD0, connectionIdLength),
                sourceConnectionId: [0x50],
                versionSpecificData: QuicHeaderTestData.BuildInitialVersionSpecificData([], [0x01], [0xAA]));

            Assert.False(QuicPacketParser.TryParseLongHeader(packet, out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0022")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_VersionNegotiation_ReadsLongerConnectionIdsFromOtherVersions()
    {
        foreach (int connectionIdLength in new[] { 21, 32, 160, 255 })
        {
            byte[] destinationConnectionId = SequentialBytes(0xD0, connectionIdLength);
            byte[] sourceConnectionId = SequentialBytes(0x50, connectionIdLength);
            byte[] packet = QuicHeaderTestData.BuildVersionNegotiation(
                headerControlBits: 0x4E,
                destinationConnectionId,
                sourceConnectionId,
                0x01020304,
                0x11223344);

            Assert.True(QuicPacketParser.TryParseVersionNegotiation(packet, out QuicVersionNegotiationPacket header));
            Assert.True(destinationConnectionId.AsSpan().SequenceEqual(header.DestinationConnectionId));
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(header.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0023")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_DestinationConnectionIdFollowsDestinationConnectionIdLength()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.DestinationConnectionIdLength, header.DestinationConnectionIdLength);
            Assert.True(SequentialBytes(0xD0, testCase.DestinationConnectionIdLength).AsSpan()
                .SequenceEqual(header.DestinationConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0025")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_LongHeader_SourceConnectionIdFollowsSourceConnectionIdLength()
    {
        foreach (LongHeaderPacketCase testCase in LongHeaderPacketCases())
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.SourceConnectionIdLength, header.SourceConnectionIdLength);
            Assert.True(SequentialBytes(0x50, testCase.SourceConnectionIdLength).AsSpan()
                .SequenceEqual(header.SourceConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0026")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberLongHeaderTypes_ContainLengthAndPacketNumberFields()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);
            PacketNumberPayloadFields fields = ParsePacketNumberPayloadFields(header, testCase.PacketType);

            Assert.Equal((ulong)(testCase.PacketNumberLength + testCase.ProtectedPayloadLength), fields.PayloadLength);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0027")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberLongHeaderTypes_ExposeTwoReservedBits()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.InRange(header.ReservedBits, (byte)0, (byte)3);
            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0029")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberLongHeaderTypes_PreserveNonZeroReservedBitsForProtocolViolationValidation()
    {
        foreach (byte reservedBits in new byte[] { 1, 2, 3 })
        {
            LongHeaderPacketCase testCase = new(
                QuicLongPacketType.Initial,
                Version: QuicVersionNegotiation.Version1,
                PacketNumberLength: 2,
                ReservedBits: reservedBits,
                DestinationConnectionIdLength: 8,
                SourceConnectionIdLength: 4,
                ProtectedPayloadLength: 16,
                TokenLength: 0);

            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);
            Assert.Equal(reservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0030")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberLongHeaderTypes_DoNotDiscardBeforeReservedBitsRemainObservable()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake
                && testCase.ReservedBits != 0))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.ReservedBits, header.ReservedBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0031")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberFieldLengthBits_EncodeOneLessThanPacketNumberLength()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);

            Assert.Equal(testCase.PacketNumberLength - 1, header.PacketNumberLengthBits);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0032")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberField_IsOneToFourBytesLong()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);
            PacketNumberPayloadFields fields = ParsePacketNumberPayloadFields(header, testCase.PacketType);

            Assert.InRange(fields.PacketNumber.Length, 1, 4);
            Assert.Equal(testCase.PacketNumberLength, fields.PacketNumber.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S17P2-0033")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_PacketNumberFieldLengthBits_MatchActualPacketNumberBytes()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases()
            .Where(static testCase => testCase.PacketType is QuicLongPacketType.Initial or QuicLongPacketType.ZeroRtt or QuicLongPacketType.Handshake))
        {
            QuicLongHeaderPacket header = AssertLongHeaderRoundTrip(testCase);
            PacketNumberPayloadFields fields = ParsePacketNumberPayloadFields(header, testCase.PacketType);

            Assert.Equal(header.PacketNumberLengthBits + 1, fields.PacketNumber.Length);
        }
    }

    private static IEnumerable<LongHeaderPacketCase> LongHeaderPacketCases()
    {
        foreach (LongHeaderPacketCase testCase in VersionOneLongHeaderPacketCases())
        {
            yield return testCase;
        }
    }

    private static IEnumerable<LongHeaderPacketCase> VersionOneLongHeaderPacketCases()
    {
        foreach (QuicLongPacketType packetType in new[]
        {
            QuicLongPacketType.Initial,
            QuicLongPacketType.ZeroRtt,
            QuicLongPacketType.Handshake,
            QuicLongPacketType.Retry,
        })
        {
            foreach (int packetNumberLength in PacketNumberLengthsFor(packetType))
            {
                foreach (byte reservedBits in ReservedBitsFor(packetType))
                {
                    yield return new LongHeaderPacketCase(
                        packetType,
                        Version: QuicVersionNegotiation.Version1,
                        packetNumberLength,
                        reservedBits,
                        DestinationConnectionIdLength: 0,
                        SourceConnectionIdLength: 0,
                        ProtectedPayloadLength: 1,
                        TokenLength: packetType == QuicLongPacketType.Initial ? 0 : 0);
                    yield return new LongHeaderPacketCase(
                        packetType,
                        Version: QuicVersionNegotiation.Version1,
                        packetNumberLength,
                        reservedBits,
                        DestinationConnectionIdLength: 8,
                        SourceConnectionIdLength: 4,
                        ProtectedPayloadLength: 16,
                        TokenLength: packetType == QuicLongPacketType.Initial ? 4 : 0);
                    yield return new LongHeaderPacketCase(
                        packetType,
                        Version: QuicVersionNegotiation.Version1,
                        packetNumberLength,
                        reservedBits,
                        DestinationConnectionIdLength: 20,
                        SourceConnectionIdLength: 20,
                        ProtectedPayloadLength: 64,
                        TokenLength: packetType == QuicLongPacketType.Initial ? 64 : 0);
                }
            }
        }
    }

    private static IEnumerable<int> PacketNumberLengthsFor(QuicLongPacketType packetType)
    {
        return packetType == QuicLongPacketType.Retry ? [0] : [1, 2, 3, 4];
    }

    private static IEnumerable<byte> ReservedBitsFor(QuicLongPacketType packetType)
    {
        return packetType == QuicLongPacketType.Retry ? [0, 1, 5, 10, 15] : [0, 1, 2, 3];
    }

    private static byte[] BuildLongHeaderPacket(LongHeaderPacketCase testCase)
    {
        return testCase.PacketType switch
        {
            QuicLongPacketType.Initial => QuicHeaderTestData.BuildLongHeader(
                BuildPacketNumberLongHeaderControlBits(testCase),
                testCase.Version,
                SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
                SequentialBytes(0x50, testCase.SourceConnectionIdLength),
                QuicHeaderTestData.BuildInitialVersionSpecificData(
                    SequentialBytes(0x70, testCase.TokenLength),
                    SequentialBytes(0x10, testCase.PacketNumberLength),
                    SequentialBytes(0xA0, testCase.ProtectedPayloadLength))),
            QuicLongPacketType.ZeroRtt => QuicHeaderTestData.BuildLongHeader(
                BuildPacketNumberLongHeaderControlBits(testCase),
                testCase.Version,
                SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
                SequentialBytes(0x50, testCase.SourceConnectionIdLength),
                QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    SequentialBytes(0x10, testCase.PacketNumberLength),
                    SequentialBytes(0xA0, testCase.ProtectedPayloadLength))),
            QuicLongPacketType.Handshake => QuicHeaderTestData.BuildLongHeader(
                BuildPacketNumberLongHeaderControlBits(testCase),
                testCase.Version,
                SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
                SequentialBytes(0x50, testCase.SourceConnectionIdLength),
                QuicHeaderTestData.BuildZeroRttVersionSpecificData(
                    SequentialBytes(0x10, testCase.PacketNumberLength),
                    SequentialBytes(0xA0, testCase.ProtectedPayloadLength))),
            QuicLongPacketType.Retry => QuicRetryPacketRequirementTestData.BuildRetryPacket(
                version: testCase.Version,
                destinationConnectionId: SequentialBytes(0xD0, testCase.DestinationConnectionIdLength),
                sourceConnectionId: SequentialBytes(0x50, testCase.SourceConnectionIdLength),
                retryToken: SequentialBytes(0x70, testCase.ProtectedPayloadLength),
                retryIntegrityTag: SequentialBytes(0xA0, QuicRetryIntegrity.RetryIntegrityTagLength),
                unusedBits: testCase.ReservedBits),
            _ => throw new ArgumentOutOfRangeException(nameof(testCase)),
        };
    }

    private static byte BuildPacketNumberLongHeaderControlBits(LongHeaderPacketCase testCase)
    {
        Assert.InRange(testCase.PacketNumberLength, 1, 4);
        Assert.InRange((int)testCase.ReservedBits, 0, 3);

        return (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | ((byte)testCase.PacketType << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | ((testCase.ReservedBits & 0x03) << 2)
            | ((testCase.PacketNumberLength - 1) & 0x03));
    }

    private static QuicLongHeaderPacket AssertLongHeaderRoundTrip(LongHeaderPacketCase testCase)
    {
        byte[] packet = BuildLongHeaderPacket(testCase);

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal(QuicHeaderForm.Long, header.HeaderForm);
        return header;
    }

    private static PacketNumberPayloadFields ParsePacketNumberPayloadFields(
        QuicLongHeaderPacket header,
        QuicLongPacketType packetType)
    {
        ReadOnlySpan<byte> versionSpecificData = header.VersionSpecificData;
        if (packetType == QuicLongPacketType.Initial)
        {
            Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes));
            versionSpecificData = versionSpecificData[(tokenLengthBytes + checked((int)tokenLength))..];
        }

        Assert.True(QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong payloadLength, out int payloadLengthBytes));

        ReadOnlySpan<byte> payload = versionSpecificData[payloadLengthBytes..];
        int packetNumberLength = (header.PacketNumberLengthBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        ReadOnlySpan<byte> packetNumber = payload[..packetNumberLength];

        return new PacketNumberPayloadFields(payloadLength, packetNumber.ToArray());
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = unchecked((byte)(seed + i));
        }

        return bytes;
    }

    private readonly record struct LongHeaderPacketCase(
        QuicLongPacketType PacketType,
        uint Version,
        int PacketNumberLength,
        byte ReservedBits,
        int DestinationConnectionIdLength,
        int SourceConnectionIdLength,
        int ProtectedPayloadLength,
        int TokenLength);

    private readonly record struct PacketNumberPayloadFields(
        ulong PayloadLength,
        byte[] PacketNumber);
}
