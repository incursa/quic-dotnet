using System.Buffers.Binary;
using System.Numerics;

namespace Incursa.Quic;

/// <summary>
/// Provides the narrow ChaCha20 block-function helper used for QUIC header protection.
/// </summary>
internal static class QuicChaCha20
{
    private const int UInt32Length = sizeof(uint);
    private const int KeyLength = 32;
    private const int MaskLength = 16;
    private const int BlockLength = 64;
    private const int StateWordCount = 16;
    private const int KeyWordCount = 8;
    private const int KeyStateOffset = 4;
    private const int CounterStateIndex = 12;
    private const int SampleWord0Offset = 0;
    private const int SampleWord1Offset = UInt32Length;
    private const int SampleWord2Offset = UInt32Length * 2;
    private const int SampleWord3Offset = UInt32Length * 3;
    private const int QuarterRoundCount = 10;
    private const int QuarterRoundRotate16 = 16;
    private const int QuarterRoundRotate12 = 12;
    private const int QuarterRoundRotate8 = 8;
    private const int QuarterRoundRotate7 = 7;
    private const int Word0 = 0;
    private const int Word1 = 1;
    private const int Word2 = 2;
    private const int Word3 = 3;
    private const int Word4 = 4;
    private const int Word5 = 5;
    private const int Word6 = 6;
    private const int Word7 = 7;
    private const int Word8 = 8;
    private const int Word9 = 9;
    private const int Word10 = 10;
    private const int Word11 = 11;
    private const int Word12 = 12;
    private const int Word13 = 13;
    private const int Word14 = 14;
    private const int Word15 = 15;
    private const uint StateConstant0 = 0x6170_7865;
    private const uint StateConstant1 = 0x3320_646e;
    private const uint StateConstant2 = 0x7962_2d32;
    private const uint StateConstant3 = 0x6b20_6574;

    internal static bool TryGenerateHeaderProtectionMask(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        if (key.Length != KeyLength
            || sample.Length < MaskLength
            || destination.Length < MaskLength)
        {
            return false;
        }

        Span<byte> block = stackalloc byte[BlockLength];
        GenerateBlock(key, sample, block);
        block[..MaskLength].CopyTo(destination);
        return true;
    }

    private static void GenerateBlock(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        Span<uint> initialState = stackalloc uint[StateWordCount];
        initialState[Word0] = StateConstant0;
        initialState[Word1] = StateConstant1;
        initialState[Word2] = StateConstant2;
        initialState[Word3] = StateConstant3;

        for (int i = 0; i < KeyWordCount; i++)
        {
            initialState[KeyStateOffset + i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * UInt32Length, UInt32Length));
        }

        initialState[CounterStateIndex] = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(SampleWord0Offset));
        initialState[Word13] = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(SampleWord1Offset));
        initialState[Word14] = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(SampleWord2Offset));
        initialState[Word15] = BinaryPrimitives.ReadUInt32LittleEndian(sample.Slice(SampleWord3Offset));

        Span<uint> workingState = stackalloc uint[StateWordCount];
        initialState.CopyTo(workingState);

        for (int round = 0; round < QuarterRoundCount; round++)
        {
            QuarterRound(ref workingState[Word0], ref workingState[Word4], ref workingState[Word8], ref workingState[Word12]);
            QuarterRound(ref workingState[Word1], ref workingState[Word5], ref workingState[Word9], ref workingState[Word13]);
            QuarterRound(ref workingState[Word2], ref workingState[Word6], ref workingState[Word10], ref workingState[Word14]);
            QuarterRound(ref workingState[Word3], ref workingState[Word7], ref workingState[Word11], ref workingState[Word15]);

            QuarterRound(ref workingState[Word0], ref workingState[Word5], ref workingState[Word10], ref workingState[Word15]);
            QuarterRound(ref workingState[Word1], ref workingState[Word6], ref workingState[Word11], ref workingState[Word12]);
            QuarterRound(ref workingState[Word2], ref workingState[Word7], ref workingState[Word8], ref workingState[Word13]);
            QuarterRound(ref workingState[Word3], ref workingState[Word4], ref workingState[Word9], ref workingState[Word14]);
        }

        for (int i = 0; i < workingState.Length; i++)
        {
            workingState[i] += initialState[i];
            BinaryPrimitives.WriteUInt32LittleEndian(destination.Slice(i * UInt32Length, UInt32Length), workingState[i]);
        }
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        a += b;
        d ^= a;
        d = BitOperations.RotateLeft(d, QuarterRoundRotate16);

        c += d;
        b ^= c;
        b = BitOperations.RotateLeft(b, QuarterRoundRotate12);

        a += b;
        d ^= a;
        d = BitOperations.RotateLeft(d, QuarterRoundRotate8);

        c += d;
        b ^= c;
        b = BitOperations.RotateLeft(b, QuarterRoundRotate7);
    }
}
