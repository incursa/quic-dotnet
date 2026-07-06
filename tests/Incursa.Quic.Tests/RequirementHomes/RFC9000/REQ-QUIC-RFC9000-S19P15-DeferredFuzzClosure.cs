// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S19P15_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_ProvidesAlternativeConnectionIds()
    {
        foreach (NewConnectionIdFrameCase testCase in FrameCases())
        {
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.Equal(QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType, BuildFrame(testCase)[0]);
            Assert.True(testCase.ConnectionId.AsSpan().SequenceEqual(frame.ConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_TypeIsSingleByteVarint18()
    {
        foreach (NewConnectionIdFrameCase testCase in FrameCases())
        {
            byte[] encoded = BuildFrame(testCase);

            Assert.Equal((byte)0x18, encoded[0]);
            AssertNewConnectionIdRoundTrip(testCase);
        }

        foreach (byte frameType in new byte[] { 0x17, 0x19, 0x1C })
        {
            byte[] invalid = BuildFrame(FrameCases().First());
            invalid[0] = frameType;
            QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(invalid);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0003")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_SequenceNumberIsVariableLengthInteger()
    {
        foreach (ulong sequenceNumber in VarintCases())
        {
            NewConnectionIdFrameCase testCase = CreateCase(sequenceNumber, retirePriorTo: 0, connectionIdLength: 8);
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.Equal(sequenceNumber, frame.SequenceNumber);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_RetirePriorToIsVariableLengthInteger()
    {
        foreach ((ulong sequenceNumber, ulong retirePriorTo) in new[]
        {
            (0UL, 0UL),
            (1UL, 0UL),
            (63UL, 1UL),
            (64UL, 63UL),
            (16_384UL, 16_383UL),
            (QuicVariableLengthInteger.MaxValue, QuicVariableLengthInteger.MaxValue),
        })
        {
            NewConnectionIdFrameCase testCase = CreateCase(sequenceNumber, retirePriorTo, connectionIdLength: 8);
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.Equal(retirePriorTo, frame.RetirePriorTo);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_LengthIsOneOctet()
    {
        foreach (int connectionIdLength in new[] { 1, 4, 8, 16, 20 })
        {
            NewConnectionIdFrameCase testCase = CreateCase(sequenceNumber: 6, retirePriorTo: 4, connectionIdLength);
            byte[] encoded = BuildFrame(testCase);
            int lengthOffset = NewConnectionIdLengthOffset(testCase.SequenceNumber, testCase.RetirePriorTo);

            Assert.Equal(connectionIdLength, encoded[lengthOffset]);
            AssertNewConnectionIdRoundTrip(testCase);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0006")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_AcceptsOnlyConnectionIdLengthsOneThroughTwenty()
    {
        foreach (int connectionIdLength in Enumerable.Range(1, 20))
        {
            Assert.Equal(connectionIdLength, AssertNewConnectionIdRoundTrip(
                CreateCase(sequenceNumber: (ulong)connectionIdLength, retirePriorTo: 0, connectionIdLength)).ConnectionId.Length);
        }

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(
            QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
                sequenceNumber: 1,
                retirePriorTo: 0,
                connectionId: [],
                statelessResetToken: QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken()));

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(
            QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
                sequenceNumber: 1,
                retirePriorTo: 0,
                connectionId: QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(21),
                statelessResetToken: QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_StatelessResetTokenIsExactlySixteenBytes()
    {
        foreach (NewConnectionIdFrameCase testCase in FrameCases())
        {
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.Equal(QuicS19P15NewConnectionIdFrameTestSupport.StatelessResetTokenLength, frame.StatelessResetToken.Length);
            Assert.True(testCase.StatelessResetToken.AsSpan().SequenceEqual(frame.StatelessResetToken));

            byte[] truncated = BuildFrame(testCase)[..^1];
            QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(truncated);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0009")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_RetirePriorToIsConnectionIdRetirementFloor()
    {
        foreach (ulong retirePriorTo in new[] { 0UL, 1UL, 3UL, 7UL })
        {
            NewConnectionIdFrameCase testCase = CreateCase(sequenceNumber: 8, retirePriorTo, connectionIdLength: 8);
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.Equal(retirePriorTo, frame.RetirePriorTo);
        }

        QuicS19P15NewConnectionIdFrameTestSupport.AssertRejects(
            QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
                sequenceNumber: 2,
                retirePriorTo: 3,
                connectionId: QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(8),
                statelessResetToken: QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken()));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_LengthOctetBoundsConnectionIdBytes()
    {
        foreach (int connectionIdLength in new[] { 1, 2, 8, 20 })
        {
            NewConnectionIdFrameCase testCase = CreateCase(sequenceNumber: 10, retirePriorTo: 1, connectionIdLength);
            byte[] encoded = BuildFrame(testCase);
            byte[] withTrailingNextFrame = [.. encoded, 0x00];

            Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(
                withTrailingNextFrame,
                out QuicNewConnectionIdFrame frame,
                out int bytesConsumed));
            Assert.Equal(encoded.Length, bytesConsumed);
            Assert.Equal(connectionIdLength, frame.ConnectionId.Length);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0012")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_PreservesConnectionIdOfDeclaredLength()
    {
        foreach (int connectionIdLength in new[] { 1, 4, 8, 12, 20 })
        {
            NewConnectionIdFrameCase testCase = CreateCase(
                sequenceNumber: (ulong)(connectionIdLength + 1),
                retirePriorTo: 0,
                connectionIdLength,
                connectionIdSeed: (byte)(0x30 + connectionIdLength));
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.True(testCase.ConnectionId.AsSpan().SequenceEqual(frame.ConnectionId));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_PreservesAssociatedStatelessResetToken()
    {
        foreach (byte tokenSeed in new byte[] { 0x40, 0x60, 0x80, 0xA0 })
        {
            NewConnectionIdFrameCase testCase = CreateCase(
                sequenceNumber: tokenSeed,
                retirePriorTo: 0,
                connectionIdLength: 8,
                tokenSeed: tokenSeed);
            QuicNewConnectionIdFrame frame = AssertNewConnectionIdRoundTrip(testCase);

            Assert.True(testCase.StatelessResetToken.AsSpan().SequenceEqual(frame.StatelessResetToken));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0016")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_ExactDuplicateFramesAreAccepted()
    {
        foreach (NewConnectionIdFrameCase testCase in FrameCases())
        {
            QuicConnectionPeerConnectionIdState state = new();
            QuicNewConnectionIdFrame frame = new(
                testCase.SequenceNumber,
                testCase.RetirePriorTo,
                testCase.ConnectionId,
                testCase.StatelessResetToken);

            Assert.True(state.TryAcceptNewConnectionId(frame, requiresZeroLengthDestinationConnectionId: false, out QuicTransportErrorCode errorCode, out bool changed));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.True(changed);

            Assert.True(state.TryAcceptNewConnectionId(frame, requiresZeroLengthDestinationConnectionId: false, out errorCode, out changed));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
            Assert.False(changed);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P15-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_NewConnectionIdFrame_SequenceNumberDistinguishesChangedDuplicates()
    {
        foreach (NewConnectionIdFrameCase testCase in FrameCases())
        {
            QuicConnectionPeerConnectionIdState state = new();
            QuicNewConnectionIdFrame original = new(
                testCase.SequenceNumber,
                testCase.RetirePriorTo,
                testCase.ConnectionId,
                testCase.StatelessResetToken);
            QuicNewConnectionIdFrame changedDuplicate = new(
                testCase.SequenceNumber,
                testCase.RetirePriorTo,
                SequentialBytes(0xD0, testCase.ConnectionId.Length),
                testCase.StatelessResetToken);

            Assert.True(state.TryAcceptNewConnectionId(original, requiresZeroLengthDestinationConnectionId: false, out QuicTransportErrorCode errorCode, out _));
            Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

            Assert.False(state.TryAcceptNewConnectionId(changedDuplicate, requiresZeroLengthDestinationConnectionId: false, out errorCode, out bool changed));
            Assert.Equal(QuicTransportErrorCode.ProtocolViolation, errorCode);
            Assert.False(changed);
        }
    }

    private static QuicNewConnectionIdFrame AssertNewConnectionIdRoundTrip(NewConnectionIdFrameCase testCase)
    {
        byte[] encoded = BuildFrame(testCase);
        Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(encoded, out QuicNewConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(testCase.SequenceNumber, parsed.SequenceNumber);
        Assert.Equal(testCase.RetirePriorTo, parsed.RetirePriorTo);
        Assert.True(testCase.ConnectionId.AsSpan().SequenceEqual(parsed.ConnectionId));
        Assert.True(testCase.StatelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken));

        byte[] destination = new byte[encoded.Length];
        Assert.True(QuicFrameCodec.TryFormatNewConnectionIdFrame(parsed, destination, out int bytesWritten));
        Assert.Equal(encoded.Length, bytesWritten);
        Assert.True(encoded.AsSpan().SequenceEqual(destination));
        return parsed;
    }

    private static int NewConnectionIdLengthOffset(ulong sequenceNumber, ulong retirePriorTo)
    {
        return QuicVarintTestData.EncodeMinimal(QuicS19P15NewConnectionIdFrameTestSupport.NewConnectionIdFrameType).Length
            + QuicVarintTestData.EncodeMinimal(sequenceNumber).Length
            + QuicVarintTestData.EncodeMinimal(retirePriorTo).Length;
    }

    private static IEnumerable<NewConnectionIdFrameCase> FrameCases()
    {
        yield return CreateCase(sequenceNumber: 1, retirePriorTo: 0, connectionIdLength: 1);
        yield return CreateCase(sequenceNumber: 6, retirePriorTo: 4, connectionIdLength: 8);
        yield return CreateCase(sequenceNumber: 63, retirePriorTo: 0, connectionIdLength: 12);
        yield return CreateCase(sequenceNumber: 64, retirePriorTo: 63, connectionIdLength: 16);
        yield return CreateCase(sequenceNumber: 16_384, retirePriorTo: 16_383, connectionIdLength: 20);
    }

    private static NewConnectionIdFrameCase CreateCase(
        ulong sequenceNumber,
        ulong retirePriorTo,
        int connectionIdLength,
        byte connectionIdSeed = 0x30,
        byte tokenSeed = 0x80)
    {
        return new NewConnectionIdFrameCase(
            sequenceNumber,
            retirePriorTo,
            QuicS19P15NewConnectionIdFrameTestSupport.CreateConnectionId(connectionIdLength, connectionIdSeed),
            QuicS19P15NewConnectionIdFrameTestSupport.CreateStatelessResetToken(tokenSeed));
    }

    private static byte[] BuildFrame(NewConnectionIdFrameCase testCase)
    {
        return QuicS19P15NewConnectionIdFrameTestSupport.BuildNewConnectionIdFrame(
            testCase.SequenceNumber,
            testCase.RetirePriorTo,
            testCase.ConnectionId,
            testCase.StatelessResetToken);
    }

    private static ulong[] VarintCases()
    {
        return [0, 1, 63, 64, 16_383, 16_384, QuicVariableLengthInteger.MaxValue];
    }

    private static byte[] SequentialBytes(byte seed, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(seed + index));
        }

        return bytes;
    }

    private readonly record struct NewConnectionIdFrameCase(
        ulong SequenceNumber,
        ulong RetirePriorTo,
        byte[] ConnectionId,
        byte[] StatelessResetToken);
}
