using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;

namespace Incursa.Quic.Tests;

internal static class QuicVariableLengthIntegerPropertyGenerators
{
    public static Arbitrary<ulong> VariableLengthIntegerValue()
    {
        return Arb.ToArbitrary(
            Gen.ArrayOf(GenerateByte(), 8)
                .Select(bytes => BinaryPrimitives.ReadUInt64BigEndian(bytes) & QuicVariableLengthInteger.MaxValue));
    }

    private static Gen<byte> GenerateByte()
    {
        return Gen.Choose(byte.MinValue, byte.MaxValue).Select(value => (byte)value);
    }
}
