using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;

namespace Incursa.Quic.Tests;

public sealed record StreamFrameScenario(
    byte FrameType,
    ulong StreamId,
    ulong Offset,
    byte[] StreamData);

public sealed record StreamAccountingScenario(
    byte FrameType,
    ulong StreamId,
    ulong Offset,
    byte[] StreamData,
    ulong ConnectionMaximumData,
    ulong MaximumStreamData,
    bool ShouldSucceed);

internal static class QuicStreamFramePropertyGenerators
{
    public static Arbitrary<StreamFrameScenario> StreamFrameScenario()
    {
        return Arb.ToArbitrary(
            from frameType in Gen.Elements((byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F)
            from streamId in GenerateRepresentableUInt64()
            from offset in Gen.Choose(0, 4096).Select(value => (ulong)value)
            from streamData in Gen.Choose(1, 16).SelectMany(length => Gen.ArrayOf(GenerateByte(), length))
            select new StreamFrameScenario(frameType, streamId, offset, streamData));
    }

    public static Arbitrary<StreamAccountingScenario> StreamAccountingScenario()
    {
        return Arb.ToArbitrary(
            from frameType in Gen.Elements((byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F)
            from streamId in GenerateRepresentableUInt64()
            from offset in Gen.Choose(0, 4096).Select(value => (ulong)value)
            from streamData in Gen.Choose(0, 16).SelectMany(length => Gen.ArrayOf(GenerateByte(), length))
            let frameEnd = offset + (ulong)streamData.Length
            from shouldSucceed in Gen.Elements(true, false)
            from connectionSlop in Gen.Choose(0, 64).Select(value => (ulong)value)
            from streamSlop in Gen.Choose(0, 64).Select(value => (ulong)value)
            select new StreamAccountingScenario(
                frameType,
                streamId,
                offset,
                streamData,
                shouldSucceed ? frameEnd + connectionSlop : (frameEnd > 0 ? frameEnd - 1 : 0),
                shouldSucceed ? frameEnd + streamSlop : (frameEnd > 0 ? frameEnd - 1 : 0),
                shouldSucceed));
    }

    private static Gen<ulong> GenerateRepresentableUInt64()
    {
        return
            from bytes in Gen.ArrayOf(GenerateByte(), 8)
            select BinaryPrimitives.ReadUInt64BigEndian(bytes) & QuicVariableLengthInteger.MaxValue;
    }

    private static Gen<byte> GenerateByte()
    {
        return Gen.Choose(byte.MinValue, byte.MaxValue).Select(value => (byte)value);
    }
}
